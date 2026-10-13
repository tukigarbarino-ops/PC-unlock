#include "keyboard.h"
#include <NimBLEDevice.h>
#include <NimBLEHIDDevice.h>

static NimBLECharacteristic* inputChr = nullptr;
static NimBLECharacteristic* sysChr = nullptr;
static NimBLECharacteristic* mouseChr = nullptr;
static NimBLECharacteristic* consChr = nullptr;
static volatile bool connected = false;

// Descriptor HID: teclado estándar (Report ID 1: modificadores + 6 teclas, LEDs de salida)
// + controles de sistema (Report ID 2: Apagar / Suspender / Despertar)
// + mouse (Report ID 3: 3 botones, X, Y, rueda, rueda horizontal) + multimedia (Report ID 4: Consumer Control).
// OJO: si se cambia este descriptor, Windows tiene que volver a emparejar (quitar el dispositivo y agregarlo).
static const uint8_t REPORT_MAP[] = {
  0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01,
  0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
  0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
  0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02,
  0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
  0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
  0xC0,
  // System Control
  0x05, 0x01, 0x09, 0x80, 0xA1, 0x01, 0x85, 0x02,
  0x19, 0x81, 0x29, 0x83, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x03, 0x81, 0x02,
  0x95, 0x05, 0x81, 0x01,
  0xC0,
  // Mouse
  0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x03, 0x09, 0x01, 0xA1, 0x00,
  0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02,
  0x95, 0x01, 0x75, 0x05, 0x81, 0x01,
  0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06,
  0x05, 0x0C, 0x0A, 0x38, 0x02, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x01, 0x81, 0x06,
  0xC0, 0xC0,
  // Consumer Control (multimedia): un uso de 16 bits
  0x05, 0x0C, 0x09, 0x01, 0xA1, 0x01, 0x85, 0x04,
  0x15, 0x00, 0x26, 0xFF, 0x03, 0x19, 0x00, 0x2A, 0xFF, 0x03, 0x75, 0x10, 0x95, 0x01, 0x81, 0x00,
  0xC0,
};

// ---- Seguridad del Bluetooth ----
// Solo se aceptan dispositivos ya emparejados. Emparejar uno nuevo se permite únicamente
// si todavía no hay ninguno, o en modo configuración (BOOT 3 s). Cualquier otro que se conecte
// se desconecta, y si llegó a crear un vínculo se borra. Las teclas solo se mandan
// cuando hay un dispositivo de confianza conectado y cifrado.
#define MAX_CONN 4
static NimBLEServer* server = nullptr;
static volatile bool pairingOpen = false;
static uint16_t trustedHandle = 0xFFFF;
struct Pending { uint16_t handle; uint32_t since; bool used; };
static Pending pending[MAX_CONN];
// NimBLE guarda el vínculo nuevo DESPUÉS de avisar que terminó el cifrado,
// así que el vínculo de un dispositivo rechazado se borra un rato más tarde, en kbLoop().
static NimBLEAddress toForget;
static uint32_t forgetAt = 0;
static uint8_t forgetTries = 0;

static Pending* findPending(uint16_t h) {
  for (auto& p : pending) if (p.used && p.handle == h) return &p;
  return nullptr;
}

class ServerCb : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* s, ble_gap_conn_desc* desc) override {
    for (auto& p : pending) {
      if (!p.used) { p = {desc->conn_handle, millis(), true}; break; }
    }
  }
  void onAuthenticationComplete(ble_gap_conn_desc* desc) override {
    if (Pending* p = findPending(desc->conn_handle)) p->used = false;
    NimBLEAddress id(desc->peer_id_addr);
    // ¿Es un dispositivo que ya estaba emparejado antes de esta conexión?
    bool known = NimBLEDevice::isBonded(id);
    bool allowNew = pairingOpen || NimBLEDevice::getNumBonds() == 0;
    if (!desc->sec_state.encrypted || !desc->sec_state.bonded || (!known && !allowNew)) {
      Serial.printf("[ble] %s no autorizado: desconectado\n", id.toString().c_str());
      if (!known) { toForget = id; forgetAt = millis() + 800; forgetTries = 5; }
      server->disconnect(desc->conn_handle);
      return;
    }
    trustedHandle = desc->conn_handle;
    connected = true;
    Serial.printf("[ble] conectado %s%s\n", id.toString().c_str(), known ? "" : " (emparejado nuevo)");
  }
  void onDisconnect(NimBLEServer* s, ble_gap_conn_desc* desc) override {
    if (Pending* p = findPending(desc->conn_handle)) p->used = false;
    if (desc->conn_handle == trustedHandle) {
      trustedHandle = 0xFFFF;
      connected = false;
      Serial.println("[ble] desconectado");
    }
  }
};

void kbAllowPairing(bool allow) { pairingOpen = allow; }
int kbBondCount() { return NimBLEDevice::getNumBonds(); }
void kbForgetAll() {
  if (server) for (uint16_t h : server->getPeerDevices()) server->disconnect(h);
  NimBLEDevice::deleteAllBonds();
}

static void inputWatchdog();

// Corta conexiones que no se cifraron a tiempo (alguien que se conecta sin emparejar)
// y borra vínculos de dispositivos rechazados.
void kbLoop() {
  inputWatchdog();
  if (forgetTries && (int32_t)(millis() - forgetAt) > 0) {
    if (NimBLEDevice::isBonded(toForget)) NimBLEDevice::deleteBond(toForget);
    forgetTries--;
    forgetAt = millis() + 1000;
  }
  for (auto& p : pending) {
    if (p.used && millis() - p.since > 15000) {
      p.used = false;
      if (server) server->disconnect(p.handle);
    }
  }
}

void kbBegin(const char* name) {
  NimBLEDevice::init(name);
  NimBLEDevice::setSecurityAuth(true, false, true);  // emparejamiento con vínculo, sin código
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);             // máxima potencia (+9 dBm)
  server = NimBLEDevice::createServer();
  server->setCallbacks(new ServerCb());
  NimBLEHIDDevice* hid = new NimBLEHIDDevice(server);
  inputChr = hid->inputReport(1);
  hid->outputReport(1);
  sysChr = hid->inputReport(2);
  mouseChr = hid->inputReport(3);
  consChr = hid->inputReport(4);
  hid->manufacturer()->setValue("PC Unlock");
  hid->pnp(0x02, 0xe502, 0xa111, 0x0210);
  hid->hidInfo(0x00, 0x01);
  hid->reportMap((uint8_t*)REPORT_MAP, sizeof(REPORT_MAP));
  hid->startServices();
  hid->setBatteryLevel(100);
  NimBLEAdvertising* adv = server->getAdvertising();
  adv->setAppearance(0x03C1);  // teclado
  adv->addServiceUUID(hid->hidService()->getUUID());
  adv->setScanResponse(false);
  adv->start();
}

bool kbConnected() { return connected; }

static void sendReport(uint8_t mod, uint8_t key) {
  if (!connected || !inputChr) return;
  uint8_t r[8] = {mod, 0, key, 0, 0, 0, 0, 0};
  inputChr->setValue(r, sizeof(r));
  inputChr->notify();
}

void kbTap(uint8_t modifiers, uint8_t key, uint16_t holdMs) {
  sendReport(modifiers, key);
  delay(holdMs);
  sendReport(0, 0);
  delay(15);
}

bool kbTypeChar(char c) {
  uint8_t mod = 0, key = 0;
  if (c >= 'a' && c <= 'z') key = 0x04 + (c - 'a');
  else if (c >= 'A' && c <= 'Z') { key = 0x04 + (c - 'A'); mod = MOD_LSHIFT; }
  else if (c >= '1' && c <= '9') key = 0x1E + (c - '1');
  else if (c == '0') key = 0x27;
  else if (c == ' ') key = HID_KEY_SPACE;
  else return false;
  kbTap(mod, key);
  return true;
}

void kbSystem(uint8_t bits) {
  if (!connected || !sysChr) return;
  uint8_t on = bits, off = 0;
  sysChr->setValue(&on, 1);
  sysChr->notify();
  delay(120);
  sysChr->setValue(&off, 1);
  sysChr->notify();
}

// ---------------------------------------------------------------- entrada remota (respaldo sin PC Unlock Host)
// Mismo protocolo binario que el host (host/src/protocol.js): 01/02 tecla abajo/arriba (uso HID), 03 dx dy,
// 04/05 botón abajo/arriba, 06 rueda v h (120 = un paso), 07 multimedia (uso Consumer), 08 soltar todo, 09 latido.

static uint8_t inMods = 0, inKeys[6] = {0}, inButtons = 0;
static int32_t wheelAcc = 0, panAcc = 0;
static uint32_t lastInput = 0;

static void sendKeys() {
  if (!connected || !inputChr) return;
  uint8_t r[8] = {inMods, 0, inKeys[0], inKeys[1], inKeys[2], inKeys[3], inKeys[4], inKeys[5]};
  inputChr->setValue(r, sizeof(r));
  inputChr->notify();
}

static void sendMouse(int dx, int dy, int wheel, int pan) {
  if (!connected || !mouseChr) return;
  do {  // movimientos grandes en varios reportes (cada eje va de -127 a 127)
    int sx = dx > 127 ? 127 : dx < -127 ? -127 : dx;
    int sy = dy > 127 ? 127 : dy < -127 ? -127 : dy;
    int sw = wheel > 127 ? 127 : wheel < -127 ? -127 : wheel;
    int sp = pan > 127 ? 127 : pan < -127 ? -127 : pan;
    uint8_t r[5] = {inButtons, (uint8_t)(int8_t)sx, (uint8_t)(int8_t)sy, (uint8_t)(int8_t)sw, (uint8_t)(int8_t)sp};
    mouseChr->setValue(r, sizeof(r));
    mouseChr->notify();
    dx -= sx; dy -= sy; wheel -= sw; pan -= sp;
  } while (dx || dy || wheel || pan);
}

static void sendConsumer(uint16_t usage) {
  if (!connected || !consChr) return;
  uint8_t on[2] = {(uint8_t)(usage & 0xFF), (uint8_t)(usage >> 8)}, off[2] = {0, 0};
  consChr->setValue(on, 2);
  consChr->notify();
  delay(20);
  consChr->setValue(off, 2);
  consChr->notify();
}

static void keyChange(uint8_t usage, bool down) {
  if (usage >= 0xE0 && usage <= 0xE7) {
    uint8_t bit = 1 << (usage - 0xE0);
    inMods = down ? (inMods | bit) : (inMods & ~bit);
  } else if (down) {
    for (uint8_t k : inKeys) if (k == usage) return;
    for (uint8_t& k : inKeys) if (!k) { k = usage; break; }  // más de 6 teclas a la vez: se ignora
  } else {
    for (uint8_t& k : inKeys) if (k == usage) k = 0;
  }
  sendKeys();
}

void kbReleaseAll() {
  bool any = inMods || inButtons;
  for (uint8_t k : inKeys) any |= k != 0;
  inMods = 0;
  memset(inKeys, 0, sizeof(inKeys));
  inButtons = 0;
  wheelAcc = panAcc = 0;
  if (any) { sendKeys(); sendMouse(0, 0, 0, 0); }
}

static void inputWatchdog() {
  bool held = inMods || inButtons;
  for (uint8_t k : inKeys) held |= k != 0;
  if (held && millis() - lastInput > 2000) {
    Serial.println("[in] sin mensajes por 2 s: suelto todo");
    kbReleaseAll();
  }
}

void kbInput(const uint8_t* b, size_t len) {
  lastInput = millis();
  size_t i = 0;
  while (i < len) {
    uint8_t op = b[i];
    auto i16 = [&](size_t o) { return (int16_t)(b[i + o] | (b[i + o + 1] << 8)); };
    switch (op) {
      case 1: case 2:
        if (i + 2 > len) return;
        keyChange(b[i + 1], op == 1);
        i += 2;
        break;
      case 3:
        if (i + 5 > len) return;
        sendMouse(i16(1), i16(3), 0, 0);
        i += 5;
        break;
      case 4: case 5:
        if (i + 2 > len) return;
        inButtons = op == 4 ? (inButtons | (b[i + 1] & 7)) : (inButtons & ~(b[i + 1] & 7));
        sendMouse(0, 0, 0, 0);
        i += 2;
        break;
      case 6: {
        if (i + 5 > len) return;
        wheelAcc += i16(1);
        panAcc += i16(3);
        int w = wheelAcc / 120, p = panAcc / 120;
        wheelAcc -= w * 120;
        panAcc -= p * 120;
        if (w || p) sendMouse(0, 0, w, p);
        i += 5;
        break;
      }
      case 7:
        if (i + 3 > len) return;
        sendConsumer((uint16_t)i16(1));
        i += 3;
        break;
      case 8: kbReleaseAll(); i += 1; break;
      case 9: i += 1; break;
      default: return;  // desconocido: se descarta el resto
    }
  }
}
