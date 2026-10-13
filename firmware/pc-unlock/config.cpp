#include "config.h"
#include <Preferences.h>

Config cfg;
static Preferences prefs;

void configLoad() {
  prefs.begin("pcu", true);
  for (int i = 0; i < MAX_WIFI; i++) {
    cfg.wifi[i].ssid = prefs.getString(("ws" + String(i)).c_str(), "");
    cfg.wifi[i].pass = prefs.getString(("wp" + String(i)).c_str(), "");
  }
  cfg.mqttHost = prefs.getString("mh", "");
  cfg.mqttPort = prefs.getUShort("mp", 8883);
  cfg.mqttUser = prefs.getString("mu", "");
  cfg.mqttPass = prefs.getString("mw", "");
  cfg.topic = prefs.getString("tp", "");
  cfg.key.rpId = prefs.getString("rp", "").c_str();
  cfg.key.origin = prefs.getString("or", "").c_str();
  cfg.key.credId = prefs.getString("ci", "").c_str();
  size_t n = prefs.getBytes("pk", cfg.key.pub, 65);
  cfg.paired = n == 65 && cfg.topic.length() && cfg.key.rpId.size() && auth::validPublicKey(cfg.key.pub);
  cfg.hasMac = prefs.getBytes("mac", cfg.pcMac, 6) == 6;
  cfg.pin = prefs.getString("pin", "");
  cfg.wakeKey = prefs.getUChar("wk", 1);
  cfg.sendEnter = prefs.getBool("en", false);
  cfg.wakeDelay = prefs.getUShort("wd", 1500);
  prefs.end();
}

void configSave() {
  prefs.begin("pcu", false);
  for (int i = 0; i < MAX_WIFI; i++) {
    prefs.putString(("ws" + String(i)).c_str(), cfg.wifi[i].ssid);
    prefs.putString(("wp" + String(i)).c_str(), cfg.wifi[i].pass);
  }
  prefs.putString("mh", cfg.mqttHost);
  prefs.putUShort("mp", cfg.mqttPort);
  prefs.putString("mu", cfg.mqttUser);
  prefs.putString("mw", cfg.mqttPass);
  prefs.putString("tp", cfg.topic);
  prefs.putString("rp", cfg.key.rpId.c_str());
  prefs.putString("or", cfg.key.origin.c_str());
  prefs.putString("ci", cfg.key.credId.c_str());
  if (cfg.paired) prefs.putBytes("pk", cfg.key.pub, 65);
  if (cfg.hasMac) prefs.putBytes("mac", cfg.pcMac, 6);
  prefs.putString("pin", cfg.pin);
  prefs.putUChar("wk", cfg.wakeKey);
  prefs.putBool("en", cfg.sendEnter);
  prefs.putUShort("wd", cfg.wakeDelay);
  prefs.end();
}

void configErase() {
  prefs.begin("pcu", false);
  prefs.clear();
  prefs.end();
  cfg = Config();
}

void setSetupFlag(bool on) {
  prefs.begin("pcu", false);
  prefs.putBool("setup", on);
  prefs.end();
}

bool getSetupFlag() {
  prefs.begin("pcu", true);
  bool v = prefs.getBool("setup", false);
  prefs.end();
  return v;
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool parseMac(const String& s, uint8_t out[6]) {
  int n = 0, hi = -1;
  for (size_t i = 0; i < s.length(); i++) {
    int v = hexval(s[i]);
    if (v < 0) continue;  // ignora ':', '-', espacios
    if (hi < 0) {
      hi = v;
    } else {
      if (n >= 6) return false;
      out[n++] = (uint8_t)(hi << 4 | v);
      hi = -1;
    }
  }
  return n == 6 && hi < 0;
}

String macToString(const uint8_t mac[6]) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}
