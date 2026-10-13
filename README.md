# PC Unlock

Prendé, desbloqueá y bloqueá tu compu desde el iPhone con **Face ID**, usando una **ESP32**.

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
| `.github/workflows/build.yml` | Compila el firmware, corre la prueba y publica todo en Pages |

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
