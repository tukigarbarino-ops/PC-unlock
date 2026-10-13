# PC Unlock — contexto del proyecto

Respondé siempre en **español rioplatense** (vos), con explicaciones paso a paso. Cuando el usuario tenga que
hacer algo en la compu, la BIOS o el celu, dale pasos numerados con los nombres exactos de menús y botones.

## Qué es

Sistema para **prender, apagar, desbloquear y bloquear** una compu con Windows desde el iPhone con **Face ID**,
gratis y sin depender de apps pagas. Está funcionando en producción desde v1.2.0.

```
iPhone (web app PWA + passkey/Face ID)
   │  orden firmada (WebAuthn, ES256)
   ▼
EMQX Cloud Serverless (MQTT, gratis)   ← TLS 8883 (ESP) / WSS 8084 path /mqtt (app)
   │
   ▼
ESP32 (WROOM-32D clásica) ── Wake-on-LAN ─────────► compu (prender)
     └── teclado BLE HID "PC Unlock" ─────────────► PIN (desbloquear), Win+L (bloquear),
                                                     System Power Down (apagar)
```

- **No se instala nada en Windows**: la ESP es un teclado Bluetooth para Windows.
- La web app está en GitHub Pages (`https://<usuario>.github.io/PC-unlock/`), repo **público**.
- Pensado para usarse en **más de una casa**: la ESP guarda hasta 3 WiFi y viaja con la compu
  (el Wake-on-LAN solo funciona dentro de la misma LAN).

## Estructura del repo

| Ruta | Qué es |
|---|---|
| `firmware/pc-unlock/` | Sketch Arduino de la ESP32 (`pc-unlock.ino`, `auth.*`, `config.*`, `portal.*`, `keyboard.*`, `certs.h`) |
| `firmware/build.sh` | Compila con arduino-cli y arma un `.bin` único (merge-bin) |
| `firmware/test/` | `verify_test.cpp` + fixtures: prueba en PC de `auth.cpp` con aserciones WebAuthn reales |
| `web/` | Web app: `index.html`, `app.js`, `style.css`, `manifest.webmanifest`, íconos, `vendor/mqtt-5.15.2.min.js` |
| `web/instalar/` | Página ESP Web Tools 10.4.0 para flashear desde el navegador (en la práctica el usuario usa el Arduino IDE) |
| `.github/workflows/build.yml` | En cada push a `main`: compila firmware, corre `verify_test`, publica `web/` + firmware en Pages |

## Firmware ESP32

### Cómo se compila (IMPORTANTE)
- Núcleo **esp32 by Espressif 2.0.17**. Con la 3.x la ESP entra en bootloop (NimBLE 1.4.3 no es compatible).
  El paquete "Arduino ESP32 Boards" (de Arduino) **no** sirve: es para la Nano ESP32.
- Librerías: **NimBLE-Arduino 1.4.3** (no 2.x, cambió la API), **PubSubClient 2.8**, **ArduinoJson 7.x**.
  El teclado BLE es propio (`keyboard.cpp`), no se usa ESP32-BLE-Keyboard.
- Placa **ESP32 Dev Module**, Partition Scheme **Huge APP (3MB No OTA/1MB SPIFFS)** (el programa pesa ~1,2 MB;
  la partición por defecto no alcanza).
- Al **actualizar**, "Erase All Flash Before Sketch Upload" en **Disabled** (si no, borra WiFi/PIN/código/vínculos BLE).
- El usuario carga el firmware con el **Arduino IDE** (la instalación web se quedaba en "Preparing installation").
  Si hace falta, mantener BOOT durante "Connecting…".
- Uso de recursos (v1.2.0): flash ~39 % de 3 MB, RAM estática ~18 %, en ejecución ~55–65 % (WiFi + BLE + TLS).
  El recurso más justo es la RAM: evitar una segunda conexión TLS.

### Modos
- **Modo configuración**: si falta configuración o si se mantiene **BOOT 3 s**. Crea el WiFi `PC-Unlock-XXXX`
  (últimos 2 bytes de la MAC de la ESP), clave `pcunlock`, portal cautivo en `http://192.168.4.1`.
  Ahí se pega el código de la app, WiFi (hasta 3), MAC de la compu, PIN, tecla para despertar
  (ninguna/Espacio/Ctrl/Esc), espera antes del PIN, Enter opcional. Botones: borrar emparejamientos BLE, borrar todo.
  Si ya estaba configurada, vuelve sola al modo normal a los 15 min. Contraseñas y PIN nunca se muestran.
- **Modo normal**: WiFiMulti → NTP → MQTT TLS (raíces en `certs.h`; EMQX Serverless usa *DigiCert Global Root CA*).
- LED (GPIO2): rápido = configuración; lento = sin WiFi; destello cada 2 s = sin MQTT; apagado = OK.
- Configuración en NVS (`Preferences`, namespace `pcu`).

### Protocolo MQTT
Temas: `pcu/<topic>/cmd` (app → ESP), `pcu/<topic>/resp` (ESP → app), `pcu/<topic>/state` (retenido, LWT `{"online":false}`).

- **Código de emparejamiento** (lo genera la app, se pega en la ESP): `PCU1.` + base64url(JSON)
  `{t: topic(16 hex), r: rpId, o: origin, k: pubkey P-256 sin comprimir (65 B, b64url), i: credId, h: host MQTT, p: 8883, u: usuario, w: contraseña}`
- **Orden** (cmd): `{"ad": authenticatorData, "cd": clientDataJSON, "sig": firma DER, "id": credId}` (todo base64url).
  El `challenge` de WebAuthn es el JSON `{"c": "<orden>", "t": <unix s>, "n": "<nonce hex>"}`.
- La ESP verifica (`auth.cpp`): `type == webauthn.get`, `origin`, `rpIdHash`, flags **UP y UV** (Face ID),
  firma ECDSA-P256 sobre `authData || SHA256(clientData)`, hora ±90 s, nonce no repetido (últimos 16).
- Órdenes: `wake`, `unlock`, `lock`, `shutdown`, `ping`.
- Respuesta: `{"n", "c", "ok", "msg"?, "pc"}`. Estado: `{"online", "pc" (BLE conectado), "ssid", "rssi", "v", "mac", "pin", "t"}`.

### Bluetooth (keyboard.cpp)
- HID con Report ID 1 = teclado (mod + 6 teclas, LEDs) y Report ID 2 = System Control (bit0 Power Down, bit1 Sleep, bit2 Wake).
  **Si se cambia el report map, Windows tiene que volver a emparejar** (quitar dispositivo + agregar en modo configuración).
- Seguridad: solo dispositivos ya vinculados. Vincular uno nuevo solo con **cero vínculos** o en **modo configuración**.
  Se decide en `onAuthenticationComplete` con `isBonded(peer_id_addr)`. Ojo: NimBLE guarda el vínculo **después**
  del evento de cifrado, por eso el vínculo de un rechazado se borra más tarde en `kbLoop()`.
  Conexiones sin cifrar se cortan a los 15 s. Potencia BLE +9 dBm.
- Teclas tipeadas con códigos HID de distribución US: letras, números y espacio coinciden con el teclado español;
  los símbolos no (habría que mapear la distribución Español-Latinoamérica).

### Requisitos en la compu (ya hechos)
BIOS: ErP Ready = Disabled, Power On By PCI-E = Enabled. Windows: Wake on Magic Packet y Shutdown Wake-On-LAN
activados en la placa de red, inicio rápido desactivado, botón de encendido = Apagar. Compu por Ethernet.

## Web app

- PWA para iOS: se agrega a inicio desde Safari. **La app instalada y Safari no comparten localStorage**:
  la configuración se hace desde el ícono.
- Config en `localStorage['pcu-config-v1']` (host/usuario/contraseña MQTT, topic, credId, rpId, origin, pub).
- Passkey: `navigator.credentials.create` (ES256, platform, UV required). Clave pública con `getPublicKey()`
  y plan B con un parser CBOR propio.
- Cada orden: `navigator.credentials.get` con el challenge de arriba → publicar en `cmd` → esperar `resp` con el mismo nonce.
  Face ID tiene que ser lo **primero** después del toque (gesto del usuario en iOS); Apagar pide doble toque
  (confirmación en la propia UI, no con `confirm()`).
- `cfg.testUrl` permite apuntar a un broker local `ws://` solo para pruebas.
- Cache-busting con `?v=` en `index.html` cuando cambian `app.js`/`style.css`.

## Pruebas que existen
- `firmware/test/verify_test.cpp`: compila `auth.cpp` contra mbedtls 2.28 + ArduinoJson y verifica aserciones
  reales (fixtures generados con Chromium + autenticador virtual de WebAuthn por CDP). Corre en CI.
- Prueba de punta a punta usada en desarrollo: Playwright + autenticador virtual, broker MQTT local (aedes con
  websocket-stream) + `testUrl`, y una "ESP falsa" en Python que valida con `verify_test`.

## Reglas
- **Repo público: nunca commitear datos personales** (MAC, IPs, emails, host de EMQX, usuarios, contraseñas, PIN,
  nombres de redes). Commits con email `noreply` de GitHub. El historial ya se reescribió una vez por esto.
- No romper lo que funciona: prender/apagar/desbloquear/bloquear tienen que seguir andando.
- Actualizaciones de firmware sin borrar la configuración; subir `FW_VERSION` en `config.h`.
- Antes de cualquier acción destructiva (borrar flash, force push, quitar vínculos) preguntar.

## Decisiones tomadas para lo próximo (todavía no implementado)
- **Pantalla, mouse y teclado dentro de la misma web app** (no apps aparte; Chrome Remote Desktop no se puede
  embeber). Requiere un programa host en Windows (ver el pedido del usuario).
- **Touchpad**: cuadrado como el de una laptop; arrastrar mueve el puntero; tocar mitad izquierda = clic izquierdo,
  mitad derecha = clic derecho; dos dedos = scroll.
- **Teclado propio dibujado en la app** (no el del iPhone): todas las letras y números, F1–F12, Esc, Tab, Enter,
  Borrar, Espacio, flechas, Supr, Inicio, Fin, RePág, AvPág, y **Ctrl, Shift, Alt, Win que se mantienen apretados
  con el dedo** (multitouch, NO "pegajosos").
- **Multimedia**: play/pausa, anterior, siguiente, volumen +/−, silencio.
- Paneles desplegables (se abren y cierran cuando el usuario quiere).
- **Sesión con Face ID**: un Face ID abre la sesión remota, dura **máximo 1 hora**. Prender/apagar/desbloquear/bloquear
  siguen pidiendo Face ID cada vez.
- Si se corta la conexión con teclas apretadas: soltar todo automáticamente a los ~2 s sin mensajes.
- Ideas anotadas para más adelante (ESP sin hardware extra): suspender, macros, presentaciones, apagado programado,
  horarios, monitor de cortes de internet, escáner WiFi, avisos por ntfy, BOOT corto como botón, sensor táctil.
  Con hardware barato: optoacoplador al botón de power (forzar apagado/reinicio), IR (aire/TV), DHT22/BME280, WS2812.
