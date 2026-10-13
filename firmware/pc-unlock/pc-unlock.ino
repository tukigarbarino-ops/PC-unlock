// PC Unlock — ESP32 que prende (Wake-on-LAN), apaga, desbloquea y bloquea la compu (teclado Bluetooth)
// con órdenes firmadas por una passkey del iPhone (Face ID), recibidas por MQTT.
//
// Modo configuración: si falta configurar, o si mantenés apretado el botón BOOT 3 segundos,
// la ESP crea el WiFi "PC-Unlock-XXXX" (clave: pcunlock) con la página de configuración.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiMulti.h>
#include <WiFiUdp.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include "keyboard.h"
#include <time.h>

#include "config.h"
#include "auth.h"
#include "portal.h"
#include "certs.h"
#include "session.h"
#include <esp_system.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/ecdsa.h>

#ifndef LED_PIN
#define LED_PIN 2
#endif
#define BOOT_PIN 0

bool bleConnected() { return kbConnected(); }

static WiFiMulti wifiMulti;
static WiFiClientSecure net;
static PubSubClient mqtt(net);

static bool setupMode = false;
static String tCmd, tResp, tState, tIn;
static sess::Session remote;  // sesión de teclado/mouse por la ESP (respaldo sin PC Unlock Host)
#define SESSION_SECS 3600

static int hwRng(void*, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}
static String pendingMsg;
static bool hasPending = false;
static uint32_t lastMqttTry = 0, mqttBackoff = 2000;
static uint32_t lastState = 0;
static bool lastBle = false;
static uint32_t lastWifiTry = 0;

// Nonces ya usados (anti-repetición)
static std::string usedNonces[16];
static int usedIdx = 0;

// ---------------------------------------------------------------- utilidades

static bool timeValid() { return time(nullptr) > 1700000000; }

static void led(bool on) { digitalWrite(LED_PIN, on ? HIGH : LOW); }

static void updateLed() {
  uint32_t ms = millis();
  if (setupMode) led((ms / 150) % 2);                     // rápido: modo configuración
  else if (!WiFi.isConnected()) led((ms / 800) % 2);      // lento: sin WiFi
  else if (!mqtt.connected()) led((ms % 2000) < 100);     // destello: sin servidor
  else led(false);                                         // apagado: todo bien
}

static void checkBootButton() {
  static uint32_t pressedAt = 0;
  if (digitalRead(BOOT_PIN) == LOW) {
    if (!pressedAt) pressedAt = millis();
    if (millis() - pressedAt > 3000) {
      Serial.println("[boot] botón BOOT 3 s -> modo configuración");
      setSetupFlag(true);
      for (int i = 0; i < 10; i++) { led(i % 2); delay(80); }
      ESP.restart();
    }
  } else {
    pressedAt = 0;
  }
}

// ---------------------------------------------------------------- acciones

static String doWake() {
  if (!cfg.hasMac) return "Falta cargar la MAC de la compu";
  if (!WiFi.isConnected()) return "La ESP no tiene WiFi";
  uint8_t pkt[102];
  memset(pkt, 0xFF, 6);
  for (int i = 0; i < 16; i++) memcpy(pkt + 6 + i * 6, cfg.pcMac, 6);
  WiFiUDP udp;
  IPAddress targets[2] = {WiFi.broadcastIP(), IPAddress(255, 255, 255, 255)};
  for (int rep = 0; rep < 3; rep++) {
    for (auto& ip : targets) {
      for (uint16_t port : {9, 7}) {
        udp.beginPacket(ip, port);
        udp.write(pkt, sizeof(pkt));
        udp.endPacket();
      }
    }
    delay(60);
  }
  return "";
}

static String doUnlock() {
  if (!cfg.pin.length()) return "Falta cargar el PIN en la ESP";
  if (!kbConnected()) return "La compu no está conectada por Bluetooth (¿apagada o sin emparejar?)";
  for (size_t i = 0; i < cfg.pin.length(); i++) {
    char c = cfg.pin[i];
    bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == ' ';
    if (!ok) return "El PIN tiene símbolos que la ESP no sabe escribir (solo letras y números)";
  }
  switch (cfg.wakeKey) {
    case 1: kbTap(0, HID_KEY_SPACE); break;
    case 2: kbTap(MOD_LCTRL, 0); break;
    case 3: kbTap(0, HID_KEY_ESC); break;
    default: break;
  }
  if (cfg.wakeKey) delay(cfg.wakeDelay);
  for (size_t i = 0; i < cfg.pin.length(); i++) {
    kbTypeChar(cfg.pin[i]);
    delay(40);
  }
  if (cfg.sendEnter) {
    delay(120);
    kbTap(0, HID_KEY_ENTER);
  }
  return "";
}

static String doLock() {
  if (!kbConnected()) return "La compu no está conectada por Bluetooth";
  kbTap(MOD_LGUI, HID_KEY_L, 120);
  return "";
}

static String doShutdown() {
  if (!kbConnected()) return "La compu no está conectada por Bluetooth (¿ya está apagada?)";
  kbSystem(SYS_POWER_DOWN);
  return "";
}

// ---------------------------------------------------------------- MQTT

static void publishState() {
  JsonDocument d;
  d["online"] = true;
  d["pc"] = kbConnected();
  d["ssid"] = WiFi.SSID();
  d["rssi"] = WiFi.RSSI();
  d["v"] = FW_VERSION;
  d["mac"] = cfg.hasMac;
  d["pin"] = cfg.pin.length() > 0;
  d["t"] = (int64_t)time(nullptr);
  if (cfg.hasId) d["k"] = auth::b64urlEncode(cfg.idPub, 65);  // clave de identidad (la app la fija comparando el código)
  d["in"] = 1;                                                 // acepta teclado/mouse/multimedia remotos
  String s;
  serializeJson(d, s);
  mqtt.publish(tState.c_str(), s.c_str(), true);
  lastState = millis();
  lastBle = kbConnected();
}

static void respond(const std::string& nonce, const String& cmd, const String& err) {
  JsonDocument d;
  d["n"] = nonce.c_str();
  d["c"] = cmd;
  d["ok"] = err.length() == 0;
  if (err.length()) d["msg"] = err;
  d["pc"] = kbConnected();
  String s;
  serializeJson(d, s);
  mqtt.publish(tResp.c_str(), s.c_str(), false);
}

// Abre la sesión de teclado/mouse: ECDH con la clave efímera de la app + firma con la identidad de la ESP.
static void openRemote(const auth::Command& c, int64_t now) {
  std::vector<uint8_t> appPub;
  if (!cfg.hasId) return respond(c.nonce, c.cmd.c_str(), "La ESP no tiene clave de identidad");
  if (!auth::b64urlDecode(c.e, appPub) || appPub.size() != 65)
    return respond(c.nonce, c.cmd.c_str(), "Falta la clave de sesión (¿la app tiene emparejada la ESP?)");
  uint32_t t0 = millis();
  uint8_t espPub[65], sig[64];
  int64_t exp = now + SESSION_SECS;
  std::string err = sess::open(remote, appPub.data(), c.nonce, exp, espPub, hwRng, nullptr);
  if (!err.empty()) return respond(c.nonce, c.cmd.c_str(), err.c_str());
  std::string espB64 = auth::b64urlEncode(espPub, 65);
  if (!sess::sign(cfg.idPriv, sess::sessionPayload(c.nonce, c.e, espB64, exp), sig, hwRng, nullptr)) {
    sess::close(remote);
    return respond(c.nonce, c.cmd.c_str(), "No se pudo firmar la sesión");
  }
  Serial.printf("[in] sesión remota abierta (%lu ms)\n", (unsigned long)(millis() - t0));
  JsonDocument d;
  d["n"] = c.nonce.c_str();
  d["c"] = c.cmd.c_str();
  d["ok"] = true;
  d["pc"] = kbConnected();
  d["e"] = espB64.c_str();
  d["s"] = auth::b64urlEncode(sig, 64).c_str();
  d["exp"] = exp;
  String s;
  serializeJson(d, s);
  mqtt.publish(tResp.c_str(), s.c_str(), false);
}

static void handleCommand(const String& msg) {
  JsonDocument d;
  if (deserializeJson(d, msg)) return;
  const char* ad = d["ad"];
  const char* cd = d["cd"];
  const char* sig = d["sig"];
  if (!ad || !cd || !sig) return;

  auth::Command c;
  std::string err = auth::verifyAssertion(cfg.key, ad, cd, sig, c);
  if (err.size()) {
    Serial.printf("[cmd] rechazada: %s\n", err.c_str());
    respond(c.nonce, c.cmd.c_str(), String("Rechazada: ") + err.c_str());
    return;
  }
  int64_t now = time(nullptr);
  if (!timeValid()) return respond(c.nonce, c.cmd.c_str(), "La ESP todavía no tiene la hora");
  if (c.t < now - 90 || c.t > now + 90) return respond(c.nonce, c.cmd.c_str(), "Orden vencida (revisá la hora del celu)");
  for (auto& n : usedNonces)
    if (n == c.nonce) return respond(c.nonce, c.cmd.c_str(), "Orden repetida");
  usedNonces[usedIdx] = c.nonce;
  usedIdx = (usedIdx + 1) % 16;

  Serial.printf("[cmd] %s\n", c.cmd.c_str());
  if (c.cmd == "rs" || c.cmd == "rr") return openRemote(c, now);
  String r;
  if (c.cmd == "wake") r = doWake();
  else if (c.cmd == "unlock") r = doUnlock();
  else if (c.cmd == "lock") r = doLock();
  else if (c.cmd == "shutdown") r = doShutdown();
  else if (c.cmd == "ping") r = "";
  else r = "Orden desconocida";
  respond(c.nonce, c.cmd.c_str(), r);
  publishState();
}

static void onMqtt(char* topic, byte* payload, unsigned int len) {
  // Entrada remota cifrada: se descifra y se manda por Bluetooth en el momento (no publica nada).
  if (tIn == topic) {
    static uint8_t plain[520];
    if (len > sizeof(plain) + 20) return;
    int n = sess::decrypt(remote, payload, len, plain, time(nullptr));
    if (n > 0) kbInput(plain, n);
    return;
  }
  // El buffer de PubSubClient se reutiliza al publicar: copiar y procesar en loop().
  if (hasPending || len > 3000) return;
  pendingMsg = String((const char*)payload, len);
  hasPending = true;
}

static void mqttConnect() {
  if (millis() - lastMqttTry < mqttBackoff) return;
  lastMqttTry = millis();
  String clientId = "pcu-" + cfg.topic.substring(0, 10) + "-esp";
  String lwt = "{\"online\":false}";
  Serial.printf("[mqtt] conectando a %s:%u...\n", cfg.mqttHost.c_str(), cfg.mqttPort);
  bool ok = mqtt.connect(clientId.c_str(), cfg.mqttUser.c_str(), cfg.mqttPass.c_str(), tState.c_str(), 1, true,
                         lwt.c_str(), true);
  if (ok) {
    Serial.println("[mqtt] conectado");
    mqtt.subscribe(tCmd.c_str(), 1);
    mqtt.subscribe(tIn.c_str(), 0);
    publishState();
    mqttBackoff = 2000;
  } else {
    Serial.printf("[mqtt] falló, estado %d\n", mqtt.state());
    mqttBackoff = min<uint32_t>(mqttBackoff * 2, 60000);
  }
}

// ---------------------------------------------------------------- setup / loop

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  pinMode(BOOT_PIN, INPUT_PULLUP);
  delay(200);
  Serial.println("\nPC Unlock " FW_VERSION);

  configLoad();
  kbBegin("PC Unlock");
  identityEnsure();  // después del Bluetooth: el RNG por hardware necesita la radio prendida
  if (cfg.hasId) Serial.printf("[id] código de verificación: %s\n", sess::verificationCode(cfg.idPub).c_str());

  if (!cfg.complete() || getSetupFlag()) {
    setupMode = true;
    kbAllowPairing(true);
    portalBegin();
    return;
  }

  tCmd = "pcu/" + cfg.topic + "/cmd";
  tResp = "pcu/" + cfg.topic + "/resp";
  tState = "pcu/" + cfg.topic + "/state";
  tIn = "pcu/" + cfg.topic + "/in";

  WiFi.mode(WIFI_STA);
  WiFi.setHostname("pc-unlock");
  for (int i = 0; i < MAX_WIFI; i++)
    if (cfg.wifi[i].ssid.length()) wifiMulti.addAP(cfg.wifi[i].ssid.c_str(), cfg.wifi[i].pass.c_str());
  configTime(0, 0, "pool.ntp.org", "time.google.com", "time.cloudflare.com");

  net.setCACert(ROOT_CAS);
  net.setHandshakeTimeout(20);
  mqtt.setServer(cfg.mqttHost.c_str(), cfg.mqttPort);
  mqtt.setBufferSize(3072);
  mqtt.setKeepAlive(30);
  mqtt.setSocketTimeout(15);
  mqtt.setCallback(onMqtt);
}

// Mide el costo de la criptografía en esta ESP (mandar "b" por el monitor serie a 115200).
static void benchmark() {
  if (!cfg.hasId) return;
  Serial.printf("[bench] heap libre %u B, mínimo histórico %u B\n", ESP.getFreeHeap(), ESP.getMinFreeHeap());
  uint8_t sig[64], esp[65];
  uint32_t t = micros();
  sess::sign(cfg.idPriv, "PCU bench", sig, hwRng, nullptr);
  Serial.printf("[bench] firma ECDSA P-256 (una vez por sesión): %lu ms\n", (unsigned long)((micros() - t) / 1000));
  // Verificar una firma ECDSA es lo que costaría pedir una firma por cada tecla
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi r, s;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  mbedtls_ecp_point_read_binary(&grp, &Q, cfg.idPub, 65);
  mbedtls_mpi_read_binary(&r, sig, 32);
  mbedtls_mpi_read_binary(&s, sig + 32, 32);
  uint8_t h[32] = {0};
  t = micros();
  mbedtls_ecdsa_verify(&grp, h, 32, &Q, &r, &s);
  Serial.printf("[bench] verificar ECDSA P-256 (lo que costaría firmar cada tecla): %lu ms\n", (unsigned long)((micros() - t) / 1000));
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  sess::Session tmp;
  t = micros();
  sess::open(tmp, cfg.idPub, "benchnonce", time(nullptr) + 60, esp, hwRng, nullptr);
  Serial.printf("[bench] abrir sesión (ECDH efímero + HKDF): %lu ms\n", (unsigned long)((micros() - t) / 1000));
  // AES-256-GCM sobre un mensaje típico (Ctrl+C = 8 B) y HMAC-SHA256 para comparar
  uint8_t msg[8] = {1, 0xE0, 1, 6, 2, 6, 2, 0xE0}, frame[4 + 8 + 16], out[8];
  const int N = 200;
  uint32_t enc = 0, dec = 0, mac = 0;
  for (int i = 1; i <= N; i++) {
    uint8_t iv[12] = {'P', 'C', 'U', 'I', (uint8_t)i, (uint8_t)(i >> 8), 0, 0, 0, 0, 0, 0};
    memcpy(frame, iv + 4, 4);
    t = micros();
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, tmp.key, 256);
    mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, 8, iv, 12, nullptr, 0, msg, frame + 4, 16, frame + 12);
    mbedtls_gcm_free(&g);
    enc += micros() - t;
    t = micros();
    int n = sess::decrypt(tmp, frame, sizeof(frame), out, time(nullptr));
    dec += micros() - t;
    if (n != 8) {
      Serial.println("[bench] ERROR descifrando");
      break;
    }
    uint8_t hm[32];
    t = micros();
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), tmp.key, 32, frame, sizeof(frame), hm);
    mac += micros() - t;
  }
  Serial.printf("[bench] por mensaje: AES-256-GCM cifrar %lu us, descifrar+verificar %lu us; HMAC-SHA256 %lu us\n",
                (unsigned long)(enc / N), (unsigned long)(dec / N), (unsigned long)(mac / N));
  Serial.printf("[bench] heap libre después: %u B\n", ESP.getFreeHeap());
}

void loop() {
  if (Serial.available() && Serial.read() == 'b') benchmark();
  checkBootButton();
  kbLoop();
  updateLed();

  if (setupMode) {
    portalLoop();
    return;
  }

  if (!WiFi.isConnected()) {
    if (millis() - lastWifiTry > 5000) {
      lastWifiTry = millis();
      if (wifiMulti.run(8000) == WL_CONNECTED)
        Serial.printf("[wifi] conectado a %s, IP %s\n", WiFi.SSID().c_str(), WiFi.localIP().toString().c_str());
    }
    delay(10);
    return;
  }

  if (!timeValid()) {  // TLS necesita la hora
    delay(50);
    return;
  }

  if (!mqtt.connected()) {
    mqttConnect();
  } else {
    mqtt.loop();
    if (hasPending) {
      String m = pendingMsg;
      hasPending = false;
      handleCommand(m);
    }
    if (kbConnected() != lastBle || millis() - lastState > 60000) publishState();
  }
  delay(5);
}
