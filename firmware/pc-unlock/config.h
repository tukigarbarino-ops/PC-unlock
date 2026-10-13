#pragma once
#include <Arduino.h>
#include "auth.h"

#define FW_VERSION "1.2.0"
#define MAX_WIFI 3

struct WifiCred {
  String ssid;
  String pass;
};

struct Config {
  WifiCred wifi[MAX_WIFI];
  String mqttHost;
  uint16_t mqttPort = 8883;
  String mqttUser;
  String mqttPass;
  String topic;          // viene del código de emparejamiento
  bool paired = false;   // hay passkey guardada
  auth::Key key;
  uint8_t pcMac[6] = {0};
  bool hasMac = false;
  String pin;
  uint8_t wakeKey = 1;     // 0 = ninguna, 1 = espacio, 2 = Ctrl, 3 = Esc
  bool sendEnter = false;  // Enter después del PIN (necesario si el PIN tiene letras)
  uint16_t wakeDelay = 1500;

  bool hasWifi() const {
    for (int i = 0; i < MAX_WIFI; i++)
      if (wifi[i].ssid.length()) return true;
    return false;
  }
  bool complete() const { return hasWifi() && mqttHost.length() && paired; }
};

extern Config cfg;

void configLoad();
void configSave();
void configErase();
bool parseMac(const String& s, uint8_t out[6]);
String macToString(const uint8_t mac[6]);

// Pedido de entrar en modo configuración en el próximo arranque.
void setSetupFlag(bool on);
bool getSetupFlag();
