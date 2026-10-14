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

- Prender/apagar/desbloquear/bloquear: **no se instala nada en Windows** (la ESP es un teclado Bluetooth).
- Vista **Remoto** (pantalla en vivo + touchpad + teclado + multimedia): requiere **PC Unlock Host** (`host/`, Electron)
  en Windows. Ver la sección "Host de Windows".
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
| `web/remote.js` | Vista Remoto: WebRTC, emparejamiento del host, touchpad, teclado LatAm, multimedia, zoom |
| `web/instalar/` | Página ESP Web Tools 10.4.0 para flashear desde el navegador (en la práctica el usuario usa el Arduino IDE) |
| `host/` | PC Unlock Host (Electron 44): `src/main.js` (MQTT, sesión, bandeja), `webauthn.js`, `identity.js`, `input.js` (SendInput vía koffi), `protocol.js`, `rtc/` (ventana oculta WebRTC), `ui/` (ventana de configuración) |
| `tools/e2e/` | Broker aedes (TCP 1883 + WS 8888) + servidor de `web/` en :8000 + `remote.e2e.js` (Playwright/Edge + host real) |
| `.github/workflows/build.yml` | En cada push a `main`: compila firmware, corre `verify_test`, publica `web/` + firmware en Pages |
| `.github/workflows/host.yml` | windows-latest: `npm ci`, `npm test`, electron-builder (NSIS). Tag `host-vX.Y.Z` → Release |

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

## Host de Windows (PC Unlock Host, `host/`)

- **Electron 44** (elegido por: WebRTC de Chromium con H.264 por hardware vía Media Foundation/NVENC, control de
  congestión incluido, `desktopCapturer`, bandeja, `setLoginItemSettings`, electron-builder). Entrada con
  **koffi** (FFI precompilado, sin compilar nada nativo) → `SendInput`. npm 11 bloquea scripts de instalación:
  `allowScripts` en `package.json` aprueba koffi, electron, electron-winstaller; el binario de Electron se baja
  con `npx install-electron` (solo para correrlo; electron-builder baja el suyo).
- Config en `%APPDATA%\PC Unlock Host\config.json`; el código PCU1 y la clave de identidad van cifrados con
  `safeStorage` (DPAPI). Instalador NSIS oneClick por usuario (sin admin), arranca con `--hidden`.
- **DPI**: `SetThreadDpiAwarenessContext(PER_MONITOR_AWARE_V2)`; el mouse se mueve en **absoluto sobre el escritorio
  virtual** (`MOUSEEVENTF_VIRTUALDESK`, normalizado con `ceil(x*65536/w)` → vuelve exacto al píxel; probado sin
  error acumulado). Teclas = **usos HID → scancodes** (`KEYEVENTF_SCANCODE`), así Windows aplica la distribución
  instalada (**Español Latinoamérica, 0000080a**). Multimedia = VK_MEDIA_*/VK_VOLUME_*.
- Variables solo para pruebas: `PCU_USERDATA`, `PCU_MQTT_URL`, `PCU_PAIR_CODE`, `PCU_SIMULATE_INPUT=1`,
  `PCU_LOG_INPUT=1`, `PCU_LOG_STATS=1`, `PCU_SESSION_SECS`, `PCU_NO_WINDOW=1`, `PCU_TEST_HOOKS=1` (simular bloqueo
  por `pcu/<t>/host/in/test`).
- Sin sesión no captura nada (la ventana WebRTC se crea por sesión y se destruye al terminar).

### Protocolo de la sesión remota
Temas: `pcu/<t>/host/state` (retenido, LWT `{"online":false}`: `online, v, id, k (clave pública 65 B b64url),
locked, sess, t`), `pcu/<t>/host/in` (app → host), `pcu/<t>/host/out` (host → app).
- **Emparejar**: la app lee `k` de `host/state` y muestra `verificationCode` = base32 Crockford de los primeros 80 bits
  de `SHA256("PCU-ID|host|" || pub)` (`XXXX-XXXX-XXXX-XXXX`); el host muestra el mismo. Al confirmar, la app guarda
  `cfg.hostKey` y `cfg.hostId` (= primeros 8 B de SHA256(pub) en hex). Si `k` cambia, la app avisa y no conecta.
- **Abrir**: la app prepara la oferta (recvonly video + DataChannels `ctl` y `in`, ICE completo, sin trickle) **al
  abrir la vista**, así el toque llama a `credentials.get` enseguida (se rehace cada 60 s). Challenge
  `{"c":"rs","t","n","f":<fingerprint sha-256 de la oferta>,"h":<hostId>,"m":<monitor>,"q":"auto"|"saver"}`.
  Mensaje `{"type":"open","sdp","ice","ad","cd","sig","id"}`. El host verifica todo + `f` == fingerprint del SDP
  + `h` == su id. Responde `{"type":"answer","n","sdp","exp","hs"}` con `hs` = ECDSA P-256 (r||s) sobre
  `PCU-HOST-ANSWER|n|fo|fa|exp`; o `{"type":"error","n","msg"}`. La app verifica `hs` con la clave fijada y `fa`.
- **Control** (`ctl`, JSON): host→app `hello{exp,locked,monitors,monitor}`, `locked{v}`, `stats{codec,hw,w,h,fps,kbps,route}`,
  `renewed{n,exp,hs}` (`PCU-HOST-RENEW|n|fo|fa|exp`), `bye{why}`, `error`; app→host `monitor{id}`, `quality{mode}`,
  `renew{ad,cd,sig}` (challenge `c:"rr"` con el mismo `f` y `h`), `pause`/`resume` (app en segundo plano), `bye`.
- Sesión máx. `SESSION_SECS` = 3600 s desde el último Face ID; si no conecta en 30 s, se descarta.
- Host 1.1.0: challenge `rs` con `r` = 30|60 (fps); ctl app→host `fps{v}` (re-captura con el tope nuevo; 60 fps → hasta
  15 Mb/s, 30 → 8 Mb/s; ahorro de datos 12 fps) y `pad{on}` → host `pad{on,err}`; `hello` trae `fps` y `pad`
  (driver disponible).
- **Joystick** (`host/src/gamepad.js`): control de Xbox 360 virtual con **ViGEmBus** (en la PC del usuario ya está, v1.21)
  hablando el protocolo de ViGEmClient con DeviceIoControl vía koffi (SetupDi para la ruta del bus, CHECK_VERSION,
  PLUGIN serial 1..16, WAIT_READY, XUSB_SUBMIT_REPORT, UNPLUG). Ojo: los punteros de salida en koffi van con
  `koffi.inout(koffi.pointer('uint32'))`. Se desenchufa al cortar la sesión; vuelve a reposo a los 2 s sin mensajes.
  `test/manual-gamepad.js` lo verifica con XInput.
- **Entrada** (`in`, binario, igual para host y ESP): `01 u` tecla abajo, `02 u` arriba (uso HID), `03 dx dy` (i16 LE),
  `04 m`/`05 m` botón abajo/arriba (1 izq, 2 der, 4 medio), `06 v h` rueda (i16, 120 = un paso), `07 uu` multimedia
  (uso Consumer u16), `08` soltar todo, `09` latido, `0A` joystick (13 B: u16 botones con bits XUSB, u8 L2, u8 R2,
  i16 LX LY RX RY, Y+ = arriba; solo host). La app manda latido cada 500 ms mientras haya algo apretado;
  el host suelta todo a los 2 s sin mensajes. La app repite teclas mantenidas (SendInput no repite).

## Pruebas que existen
- `firmware/test/verify_test.cpp`: compila `auth.cpp` contra mbedtls 2.28 + ArduinoJson y verifica aserciones
  reales (fixtures generados con Chromium + autenticador virtual de WebAuthn por CDP). Corre en CI.
- `host/test/*.test.js` (`npm test`, corre en CI): verificación WebAuthn con los **mismos fixtures** que la ESP,
  fingerprint DTLS, identidad, protocolo de entrada, soltar a los 2 s. `host/test/manual-input.js`: SendInput real
  e inofensivo (solo en la PC).
- `tools/e2e/remote.e2e.js`: Playwright (canal `msedge`, que trae H.264; `E2E_CHANNEL=` usa Chromium) con autenticador
  virtual por CDP + broker aedes + **host real** con entrada simulada (`E2E_HOST_EXE` prueba el `.exe` empaquetado,
  `E2E_SHOTS=<dir>` guarda capturas — ojo: muestran la pantalla real, no commitearlas). 27 verificaciones, incluye
  ataques desde el broker (`aedes.authorizeForward` altera la respuesta del host).

## Reglas
- **Repo público: nunca commitear datos personales** (MAC, IPs, emails, host de EMQX, usuarios, contraseñas, PIN,
  nombres de redes). Commits con email `noreply` de GitHub. El historial ya se reescribió una vez por esto.
- No romper lo que funciona: prender/apagar/desbloquear/bloquear tienen que seguir andando.
- Actualizaciones de firmware sin borrar la configuración; subir `FW_VERSION` en `config.h`.
- Antes de cualquier acción destructiva (borrar flash, force push, quitar vínculos) preguntar.

## Decisiones de la vista Remoto (fase 1 implementada: host + web app)
- **Pantalla, mouse y teclado dentro de la misma web app** (no apps aparte; Chrome Remote Desktop no se puede
  embeber). Implementado con PC Unlock Host (`host/`).
- Video con `playsinline` y `muted`. Distribución del teclado: **Español (Latinoamérica)**.
- Pedidos del usuario ya hechos (13/10): horizontal tipo laptop (video izq., teclado compacto arriba + touchpad abajo,
  sin superponer; media query `(orientation: landscape) and (max-height: 600px)`), ⛶ solo esconde la barra, teclado
  compacto con capas ?123/#+= (símbolos mandan su combinación LatAm), clic sostenido = tocar y volver a apoyar
  (350 ms) con el mismo botón, doble toque = doble clic, bloqueo de gestos de iOS (`touchstart` con preventDefault no
  pasivo + `user-select: none` + `-webkit-touch-callout: none`), selector 30/60 fps, joystick DualSense superpuesto
  (en horizontal oculta la columna derecha), L3/R3 con botón propio o doble toque en la palanca (300 ms) y mantener.
  Ojo con nombres de clase: `.down` = apretado (no usarlo para posiciones).
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

## Respaldo por la ESP (fase 2, firmware 1.3.0 — cargado en la ESP, Bluetooth re-emparejado)
- Report map nuevo: ID 3 mouse (3 botones, X, Y, rueda, AC Pan; 5 B) e ID 4 Consumer Control (u16).
  **Hay que volver a emparejar el Bluetooth en Windows** (quitar "PC Unlock" y agregarlo en modo configuración).
- Identidad de la ESP: P-256 en NVS (`ik`), se crea sola después de `kbBegin` (RNG por hardware). Código de
  verificación (`PCU-ID|esp|`) en el portal; clave pública en `state.k` (+ `state.in=1`). "Borrar todo" la regenera.
- Sesión: challenge `rs`/`rr` con `e` = clave ECDH efímera de la app (WebCrypto, no extraíble, se crea antes del toque).
  La ESP hace ECDH + HKDF-SHA256 (salt = nonce, info `PCU-ESP-SESSION`) → AES-256-GCM, y responde en `resp`
  `{n,c,ok,pc,e,s,exp}` con `s` = firma de su identidad sobre `PCU-ESP-SESSION|n|appE|espE|exp`. 1 hora.
- Entrada: `pcu/<t>/in` (QoS 0) = seq u32 LE || GCM(protocolo binario || tag), IV `PCUI`||seq||0000; seq creciente.
  Se descifra en el callback de MQTT y va directo a `kbInput()`; suelta todo a los 2 s sin mensajes.
- App: un Face ID abre host + ESP; la entrada va por el host salvo que no esté o la compu esté bloqueada (ahí la ESP,
  que sí llega a la pantalla de bloqueo). Por la ESP: mouse a ~25 Hz y ×0,6, sin repetición de teclas en la app.
- Benchmark: mandar `b` por el monitor serie (115200). Medido en la WROOM-32D: verificar ECDSA 294 ms, firmar 291 ms,
  abrir sesión (ECDH+HKDF) 566 ms → abrir una sesión cuesta ~1,2 s una vez; por mensaje AES-256-GCM descifrar+verificar
  101 µs (cifrar 117 µs), HMAC-SHA256 249 µs. Firmar cada tecla con ECDSA (294 ms) habría dado ~3 teclas/s: descartado.
  Heap libre 92 KB (mínimo histórico 76 KB), sin cambio después de abrir sesión.
- Pruebas: `firmware/test/session_test.cpp` + `session_interop.mjs` (C++ vs WebCrypto, en CI);
  `tools/e2e/esp.e2e.js` (ESP falsa con session_test real; `E2E_SESSION_BIN=<ruta>`). En esta PC se compila con
  `python -m ziglang c++` + mbedtls 2.28.8 (no hay g++).
- arduino-cli: el del Arduino IDE (`%LOCALAPPDATA%\Programs\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe`)
  con `--config-file ~/.arduinoIDE/arduino-cli.yaml`. v1.3.0: flash 39 %, RAM estática 17 %. ESP en COM4.
