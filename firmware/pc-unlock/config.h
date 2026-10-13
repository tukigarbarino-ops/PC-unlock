#pragma once
#include <Arduino.h>
#include "auth.h"

#define FW_VERSION "1.3.0"
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
  // Clave de identidad de la ESP (P-256) para la sesión de teclado/mouse remota. Se genera sola la primera vez
  // y la app la fija comparando el código de verificación del portal. "Borrar todo" la regenera.
  uint8_t idPriv[32] = {0};
  uint8_t idPub[65] = {0};
  bool hasId = false;

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

// Carga o crea la clave de identidad (necesita el RNG por hardware: llamar con el Bluetooth ya iniciado).
void identityEnsure();

// Pedido de entrar en modo configuración en el próximo arranque.
void setSetupFlag(bool on);
bool getSetupFlag();
