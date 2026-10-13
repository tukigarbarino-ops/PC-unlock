# PC Unlock

Prendé, desbloqueá y bloqueá tu compu desde el iPhone con **Face ID**, usando una **ESP32**.
Y, si instalás **PC Unlock Host** en Windows, también **ver la pantalla en vivo y manejarla** (touchpad, teclado
y multimedia) desde la misma app.

```
iPhone (web app + passkey/Face ID)
   │  orden firmada
   ▼
Servidor MQTT (EMQX Cloud, gratis)
   │
   ▼
ESP32 ── Wake-on-LAN ──► compu (prender)
     └── teclado Bluetooth ──► escribe el PIN (desbloquear) / Win+L (bloquear)
```

- **Prender, apagar, desbloquear y bloquear.** Apagar usa la tecla de sistema "Power Down" (igual que el botón de encendido).
- **Nada que instalar en Windows.** La ESP se empareja como teclado Bluetooth ("PC Unlock").
- **Seguridad:** cada orden se firma con una passkey del iPhone que solo se usa pasando Face ID.
  La ESP verifica la firma (ECDSA P-256), el origen, que haya habido Face ID, la hora (±90 s)
  y que la orden no se haya usado antes. El PIN queda guardado solo en la ESP.
- **Bluetooth cerrado:** solo se aceptan dispositivos ya emparejados. Emparejar uno nuevo solo se puede
  si no hay ninguno o en modo configuración (BOOT 3 s); cualquier otro se desconecta y se borra su vínculo.
- **Dos casas:** la ESP guarda hasta 3 redes WiFi y se conecta sola a la que encuentre.
  Tiene que estar en la misma red que la compu (el Wake-on-LAN no cruza internet).

## Partes

| Carpeta | Qué es |
|---|---|
| `firmware/pc-unlock/` | Programa de la ESP32 (Arduino, núcleo ESP32 2.0.17) |
| `firmware/test/` | Prueba en PC de la verificación de firmas, con aserciones WebAuthn reales |
| `web/` | Web app (se publica en GitHub Pages) |
| `web/instalar/` | Página para cargar el programa en la ESP desde Chrome/Edge |
| `host/` | **PC Unlock Host**: programa de Windows (Electron) para la pantalla remota |
| `tools/e2e/` | Pruebas de punta a punta (broker local + Playwright con Face ID virtual + host real) |
| `.github/workflows/build.yml` | Compila el firmware, corre la prueba y publica todo en Pages |
| `.github/workflows/host.yml` | Compila y prueba el host; con un tag `host-vX.Y.Z` publica el instalador como Release |

## Puesta en marcha

1. **GitHub Pages:** en el repo, *Settings → Pages → Source: GitHub Actions*. Cada push a `main` publica
   la app en `https://<usuario>.github.io/<repo>/`.
2. **EMQX Cloud:** cluster *Serverless* gratis + un usuario en *Access Control → Authentication*.
3. **iPhone:** abrí la app en Safari → Compartir → *Agregar a inicio*. Desde el ícono:
   Configuración → datos de EMQX → *Crear llave con Face ID* → *Copiar código*.
4. **ESP32:** en la compu, abrí `…/instalar/` con Chrome o Edge y tocá *Instalar*.
5. **Configurar la ESP:** conectá el iPhone al WiFi `PC-Unlock-XXXX` (clave `pcunlock`), pegá el código,
   y cargá tus redes WiFi (2.4 GHz), la MAC de la compu y el PIN.
6. **Windows:** Configuración → Bluetooth → Agregar dispositivo → *PC Unlock*.

Para volver a configurar: mantener apretado **BOOT** 3 segundos con la ESP andando.

### LED de la placa
- Parpadeo rápido: modo configuración
- Parpadeo lento: buscando WiFi
- Destello cada 2 s: sin conexión al servidor MQTT
- Apagado: todo bien

## Compilar con el Arduino IDE

1. Placas: **esp32 by Espressif Systems, versión 2.0.17** (no la 3.x).
2. Librerías (Gestor de librerías): **NimBLE-Arduino 1.4.3** (no la 2.x), **PubSubClient 2.8**, **ArduinoJson 7.x**.
3. Abrí `firmware/pc-unlock/pc-unlock.ino`, placa **ESP32 Dev Module**,
   Partition Scheme **Huge APP (3MB No OTA/1MB SPIFFS)**, tu puerto COM, y **Subir**.

Con arduino-cli: `FQBN=esp32:esp32:esp32 ./firmware/build.sh build`


## Pantalla remota (PC Unlock Host)

```
iPhone (vista "Remoto")
 ├── MQTT (el mismo EMQX) ── señalización firmada ──► PC Unlock Host (bandeja de Windows)
 └── WebRTC directo (STUN; TURN opcional)
        video H.264 (por hardware) ◄── captura del monitor
        DataChannel ──► mouse / teclado / multimedia ──► SendInput
```

- **Video** de la pantalla (H.264 con aceleración por hardware si la placa de video la tiene), calidad adaptable
  y modo **Ahorro de datos** (~300 kb/s) para datos móviles. Zoom con dos dedos, doble toque = sin zoom,
  pantalla completa y vista horizontal. Si hay varios monitores, se elige cuál ver.
- **Touchpad** cuadrado: arrastrar mueve el puntero (con aceleración), tocar la mitad izquierda = clic izquierdo,
  la mitad derecha = clic derecho, dos dedos = scroll (o un toque con dos dedos = clic derecho),
  tocar y volver a apoyar = arrastrar con el clic apretado.
- **Teclado propio** con la distribución **Español (Latinoamérica)**: letras, Ñ, números y símbolos, F1–F12, Esc,
  Tab, Enter, Borrar, Espacio, flechas, Ins, Supr, Inicio, Fin, RePág, AvPág, ImpPnt. **Ctrl, Shift, Alt, AltGr y Win
  están apretados solo mientras tenés el dedo encima** (multitouch): para Ctrl+C apoyás Ctrl con un dedo y tocás C
  con otro. Mantener una tecla la repite.
- **Multimedia:** anterior, play/pausa, siguiente, silencio, volumen − y +.
- Touchpad, teclado y multimedia son paneles que abrís y cerrás con los botones de arriba.
- **Compu bloqueada:** Windows no deja ver ni controlar la pantalla de bloqueo. La app muestra un aviso con
  el botón **Desbloquear** (por la ESP, con su propio Face ID).
- Si se corta la conexión con algo apretado, el host suelta todo a los ~2 s.

### Seguridad de la sesión
- Abrir la sesión pide **Face ID**: la passkey firma un challenge con el **fingerprint DTLS** de la oferta WebRTC
  y el id de la compu. El host lo verifica igual que la ESP (origen, rpId, Face ID, firma, hora ±90 s, nonce)
  y además que el fingerprint sea el de la oferta que llegó.
- El host tiene su **propia clave de identidad** (P-256, guardada cifrada con DPAPI). La app la fija al emparejar
  **comparando un código de verificación** y después exige que cada respuesta venga firmada con ella
  (incluye el fingerprint DTLS del host). Así, ni quien controle el broker MQTT puede meterse en el medio:
  el cifrado de WebRTC (DTLS-SRTP) queda atado a las dos claves.
- La sesión dura **como máximo 1 hora**. 5 minutos antes la app ofrece **Renovar con Face ID** (sin cortar el video).
- Cuando se abre una sesión, Windows muestra una notificación; se puede cortar desde la bandeja.
- Prender, apagar, desbloquear y bloquear siguen pidiendo Face ID cada vez.

### Instalar y probar (paso a paso)
1. **Instalador:** en GitHub, pestaña **Releases** → la última `host-v…` → descargá `PC-Unlock-Host-Setup-….exe`
   (o el link "PC Unlock Host" en *Ajustes → Compu*). Ejecutalo. Si aparece **"Windows protegió su PC"**:
   **Más información → Ejecutar de todos modos** (el instalador no está firmado). Se instala solo para tu usuario,
   sin pedir administrador, queda en la **bandeja** (al lado del reloj) y arranca solo al iniciar sesión.
2. **Código:** en el iPhone, *PC Unlock → ⚙ → 3. Código para la ESP → Copiar código*. Pasalo a la compu
   (WhatsApp Web, mail a vos mismo…) y pegalo en la ventana de PC Unlock Host → **Guardar**.
   Arriba tiene que decir *Servidor: conectado*.
3. **Emparejar:** en el iPhone, *⚙ → 4. Compu (pantalla remota)*. Aparece un código como `K7F2-9QXA-3M8D-T1VW`.
   Si es **igual** al de la ventana del host (sección 2), tocá **Coinciden**. Si no es igual, no lo confirmes.
4. **Usar:** en la pantalla principal tocá **Pantalla remota**. Cuando diga *Listo para conectar*, tocá
   **Conectar con Face ID**. Abrí los paneles que quieras (Touchpad / Teclado / Multimedia).
5. Para cortar: **Cortar** en la app, o *clic derecho en el ícono de la bandeja → Cortar sesión remota*.

### TURN (si con datos móviles no conecta)
Por defecto se usa STUN público (Google y Cloudflare), que alcanza en la mayoría de las redes. Si con datos móviles
queda en "Conectando…", hace falta un servidor **TURN** que retransmita el video. Opciones gratis:
- **Metered Open Relay** (metered.ca/tools/openrelay): 20 GB por mes gratis, usuario y contraseña fijos, puertos 80/443.
  Es lo más fácil: creás la cuenta y copiás los datos en *⚙ → TURN*.
- **Cloudflare Realtime TURN**: 1.000 GB por mes gratis (compartidos con su SFU), después USD 0,05/GB. Las credenciales
  se generan con su API y vencen, así que hay que renovarlas cada tanto.
- **coturn propio** en una VM *Always Free* de Oracle Cloud (10 TB de tráfico por mes): lo más robusto, pero hay que
  mantener el servidor.

Con TURN el video pasa por ese servidor: 1 hora en modo normal son ~0,7–1,8 GB; en **Ahorro de datos** ~135 MB.

### Limitaciones
- Pantalla de bloqueo, UAC y Ctrl+Alt+Supr: Windows no deja capturarlas ni mandarles teclas.
- Ventanas de administrador (Administrador de tareas, consolas elevadas): Windows no deja que un programa común
  les mande mouse/teclado.
- Antes de iniciar sesión en Windows el host no está corriendo.

### Desarrollo del host
```
cd host
npm install
npm test          # verificación WebAuthn (mismos fixtures que la ESP), protocolo de entrada, soltar a los 2 s
npm start         # corre el host
npm run dist      # arma dist/PC-Unlock-Host-Setup-<versión>.exe
node test/manual-input.js   # prueba real e inofensiva de SendInput (mueve el puntero y lo devuelve; Shift)
```
Publicar una versión: subir `version` en `host/package.json`, commit, y `git tag host-vX.Y.Z && git push --tags`.

### Prueba de punta a punta
`tools/e2e/remote.e2e.js` levanta un broker MQTT local, sirve `web/`, abre la app en Edge con un autenticador
WebAuthn virtual y corre el **host real** (entrada simulada). Verifica emparejamiento, video, touchpad, teclado
multitouch, multimedia, soltar a los 2 s, aviso de bloqueo, renovación, vencimiento y ataques desde el broker
(fingerprint cambiado, challenge para otra compu, aserción vieja o repetida, respuesta del host alterada,
host impostor).
```
cd tools/e2e && npm install && npx playwright install chromium
node remote.e2e.js
```
