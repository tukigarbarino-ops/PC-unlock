#include "portal.h"
#include "config.h"
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>

extern bool bleConnected();
#include "keyboard.h"

static WebServer server(80);
static DNSServer dns;
static String scanned;  // <option> de redes encontradas
static uint32_t startedAt = 0;
static uint32_t restartAt = 0;

static const char AP_PASS[] = "pcunlock";

static String esc(const String& s) {
  String o;
  o.reserve(s.length() + 8);
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '&') o += "&amp;";
    else if (c == '<') o += "&lt;";
    else if (c == '>') o += "&gt;";
    else if (c == '"') o += "&quot;";
    else if (c == '\'') o += "&#39;";
    else o += c;
  }
  return o;
}

static const char CSS[] PROGMEM = R"CSS(
*{box-sizing:border-box}body{margin:0;font:16px/1.45 -apple-system,system-ui,sans-serif;background:#0f1115;color:#e8eaed}
main{max-width:520px;margin:0 auto;padding:16px}h1{font-size:22px;margin:4px 0 2px}h2{font-size:16px;margin:0 0 10px;color:#9fb3ff}
.sub{color:#9aa0a6;font-size:13px;margin-bottom:14px}.card{background:#181b22;border:1px solid #262a33;border-radius:14px;padding:14px;margin:12px 0}
label{display:block;font-size:13px;color:#9aa0a6;margin:10px 0 4px}input,select,textarea{width:100%;padding:11px;border-radius:10px;border:1px solid #333845;background:#0f1115;color:#e8eaed;font:inherit}
textarea{min-height:90px;font:12px ui-monospace,monospace;word-break:break-all}.row{display:flex;gap:8px}.row>*{flex:1}
.chk{display:flex;gap:10px;align-items:center;margin-top:10px;font-size:14px;color:#e8eaed}.chk input{width:auto}
button{width:100%;padding:13px;border:0;border-radius:12px;font:600 16px system-ui;margin-top:8px;background:#5b7cfa;color:#fff}
button.sec{background:#262a33;color:#e8eaed}button.danger{background:#5a1f24;color:#ffb4b4}
.ok{color:#7ee2a8}.bad{color:#ffb4b4}.hint{font-size:12px;color:#9aa0a6;margin-top:6px}.msg{padding:12px;border-radius:12px;background:#1d2a1f;color:#7ee2a8;margin:12px 0}
.err{background:#2a1d1d;color:#ffb4b4}
)CSS";

static void sendPage(const String& msg = "", bool isErr = false) {
  String h;
  h.reserve(9000);
  h += F("<!doctype html><html lang=es><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         "<title>PC Unlock</title><style>");
  h += FPSTR(CSS);
  h += F("</style></head><body><main><h1>PC Unlock</h1><div class=sub>Versión " FW_VERSION " · ESP ");
  h += WiFi.macAddress();
  h += F("</div>");
  if (msg.length()) {
    h += isErr ? F("<div class='msg err'>") : F("<div class=msg>");
    h += esc(msg);
    h += F("</div>");
  }
  h += F("<form method=post action=/save>");

  // 1. Código de la app
  h += F("<div class=card><h2>1. Código de la app del celu</h2>");
  if (cfg.paired) {
    h += F("<div class='ok'>✔ Ya hay un celu emparejado.</div><div class=hint>Pegá un código nuevo solo si querés reemplazarlo.</div>");
  } else {
    h += F("<div class=hint>En la app: Configuración → Crear llave con Face ID → Copiar código. Pegalo acá.</div>");
  }
  h += F("<label>Código (empieza con PCU1.)</label><textarea name=code autocapitalize=off autocorrect=off spellcheck=false></textarea></div>");

  // 2. WiFi
  h += F("<div class=card><h2>2. Redes WiFi (2.4 GHz)</h2><div class=hint>Cargá el WiFi de cada casa. Se conecta sola a la que encuentre.</div>");
  h += F("<datalist id=nets>");
  h += scanned;
  h += F("</datalist>");
  for (int i = 0; i < MAX_WIFI; i++) {
    h += F("<label>Red ");
    h += String(i + 1);
    h += F("</label><div class=row><input name=s");
    h += String(i);
    h += F(" list=nets placeholder='Nombre' autocapitalize=off value=\"");
    h += esc(cfg.wifi[i].ssid);
    h += F("\"><input type=password name=p");
    h += String(i);
    h += F(" placeholder='");
    h += cfg.wifi[i].pass.length() ? F("(sin cambios)") : F("Contraseña");
    h += F("'></div>");
  }
  h += F("<label class=chk><input type=checkbox name=clrw value=1> Borrar las contraseñas de las redes que deje vacías</label></div>");

  // 3. Compu
  h += F("<div class=card><h2>3. Tu compu</h2><label>MAC de la placa de red (Ethernet)</label><input name=mac placeholder='AA:BB:CC:DD:EE:FF' autocapitalize=characters value=\"");
  if (cfg.hasMac) h += macToString(cfg.pcMac);
  h += F("\"><label>PIN de Windows</label><input type=password name=pin inputmode=text placeholder='");
  h += cfg.pin.length() ? F("(sin cambios)") : F("Tu PIN");
  h += F("'><label class=chk><input type=checkbox name=enter value=1");
  if (cfg.sendEnter) h += F(" checked");
  h += F("> Apretar Enter después del PIN (solo si tu PIN tiene letras)</label>"
         "<label>Tecla para sacar la pantalla de bloqueo</label><select name=wk>");
  const char* keys[] = {"Ninguna", "Espacio", "Ctrl", "Esc"};
  for (int i = 0; i < 4; i++) {
    h += F("<option value=");
    h += String(i);
    if (cfg.wakeKey == i) h += F(" selected");
    h += ">";
    h += keys[i];
    h += F("</option>");
  }
  h += F("</select><label>Espera antes de escribir el PIN (ms)</label><input type=number name=wd min=200 max=8000 value=");
  h += String(cfg.wakeDelay);
  h += F("><div class=hint>Bluetooth con la compu: ");
  h += bleConnected() ? F("<span class=ok>conectado</span>") : F("<span class=bad>no conectado</span> (emparejá \"PC Unlock\" desde Configuración → Bluetooth de Windows)");
  h += F("<br>Dispositivos emparejados: ");
  h += String(kbBondCount());
  h += F(" · <b>Mientras esta página está abierta se pueden emparejar dispositivos nuevos.</b>");
  h += F("</div></div><button>Guardar y reiniciar</button></form>"
         "<form method=post action=/reboot><button class=sec>Salir sin cambios</button></form>"
         "<div class=card><h2>Bluetooth</h2><div class=hint>Si cambiaste de compu o Windows no la reconoce, borrá los emparejamientos y volvé a agregar \"PC Unlock\" desde Windows.</div>"
         "<form method=post action=/forgetbt><button class=sec>Borrar emparejamientos Bluetooth</button></form></div>"
         "<div class=card><h2>Borrar todo</h2><form method=post action=/reset onsubmit=\"return confirm('¿Borrar toda la configuración?')\">"
         "<button class=danger>Borrar configuración</button></form></div></main></body></html>");
  server.send(200, "text/html; charset=utf-8", h);
}

static void handleSave() {
  Config next = cfg;

  // Código de emparejamiento (opcional si ya hay uno)
  String code = server.arg("code");
  code.trim();
  if (code.length()) {
    auth::Pairing p;
    std::string e = auth::parsePairCode(code.c_str(), p);
    if (e.size()) return sendPage(String("Código: ") + e.c_str(), true);
    next.topic = p.topic.c_str();
    next.key = p.key;
    next.paired = true;
    if (p.mqttHost.size()) next.mqttHost = p.mqttHost.c_str();
    if (p.mqttUser.size()) next.mqttUser = p.mqttUser.c_str();
    if (p.mqttPass.size()) next.mqttPass = p.mqttPass.c_str();
    next.mqttPort = p.mqttPort;
  }

  bool clearEmpty = server.arg("clrw") == "1";
  for (int i = 0; i < MAX_WIFI; i++) {
    String s = server.arg("s" + String(i));
    String pw = server.arg("p" + String(i));
    s.trim();
    if (s != next.wifi[i].ssid) next.wifi[i].pass = "";  // otra red: no reutilizar la contraseña
    next.wifi[i].ssid = s;
    if (pw.length()) next.wifi[i].pass = pw;
    else if (clearEmpty) next.wifi[i].pass = "";
    if (!s.length()) next.wifi[i].pass = "";
  }

  String mac = server.arg("mac");
  mac.trim();
  if (mac.length()) {
    if (!parseMac(mac, next.pcMac)) return sendPage("La MAC no es válida (ej. AA:BB:CC:DD:EE:FF)", true);
    next.hasMac = true;
  }
  String pin = server.arg("pin");
  if (pin.length()) next.pin = pin;
  next.sendEnter = server.arg("enter") == "1";
  int wk = server.arg("wk").toInt();
  next.wakeKey = (wk >= 0 && wk <= 3) ? wk : 1;
  int wd = server.arg("wd").toInt();
  next.wakeDelay = constrain(wd, 200, 8000);

  if (!next.hasWifi()) return sendPage("Falta cargar al menos una red WiFi", true);
  if (!next.paired) return sendPage("Falta pegar el código de la app", true);
  if (!next.mqttHost.length()) return sendPage("El código no trae el servidor MQTT. Cargalo en la app y generá el código de nuevo.", true);

  cfg = next;
  configSave();
  setSetupFlag(false);
  restartAt = millis() + 2500;
  String m = "Guardado. La ESP se reinicia y se conecta a tu WiFi.";
  if (!cfg.pin.length()) m += " Ojo: no cargaste el PIN, así que no va a poder desbloquear.";
  if (!cfg.hasMac) m += " Ojo: sin MAC no va a poder prender la compu.";
  sendPage(m);
}

static void redirectHome() {
  server.sendHeader("Location", "http://192.168.4.1/", true);
  server.send(302, "text/plain", "");
}

void portalBegin() {
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  // Buscar redes para sugerirlas en el formulario
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n && i < 25; i++) {
    String s = WiFi.SSID(i);
    if (!s.length() || scanned.indexOf("\"" + esc(s) + "\"") >= 0) continue;
    scanned += "<option value=\"" + esc(s) + "\">";
  }
  WiFi.scanDelete();

  uint8_t m[6];
  WiFi.macAddress(m);
  char ssid[24];
  snprintf(ssid, sizeof(ssid), "PC-Unlock-%02X%02X", m[4], m[5]);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(ssid, AP_PASS);
  dns.start(53, "*", IPAddress(192, 168, 4, 1));

  server.on("/", HTTP_GET, []() { sendPage(); });
  server.on("/save", HTTP_POST, handleSave);
  server.on("/reboot", HTTP_POST, []() {
    setSetupFlag(false);
    sendPage("Reiniciando…");
    restartAt = millis() + 1500;
  });
  server.on("/forgetbt", HTTP_POST, []() {
    kbForgetAll();
    sendPage("Emparejamientos borrados. En Windows quitá \"PC Unlock\" y agregalo de nuevo.");
  });
  server.on("/reset", HTTP_POST, []() {
    kbForgetAll();
    configErase();
    sendPage("Configuración borrada. Reiniciando en modo configuración…");
    setSetupFlag(true);
    restartAt = millis() + 1500;
  });
  server.onNotFound(redirectHome);  // portal cautivo: cualquier URL lleva a la página
  server.begin();
  startedAt = millis();
  Serial.printf("[setup] WiFi '%s' clave '%s' -> http://192.168.4.1\n", ssid, AP_PASS);
}

void portalLoop() {
  dns.processNextRequest();
  server.handleClient();
  if (restartAt && (int32_t)(millis() - restartAt) > 0) ESP.restart();
  // Si ya estaba configurada, no quedarse para siempre en modo configuración.
  if (cfg.complete() && millis() - startedAt > 15UL * 60 * 1000) {
    setSetupFlag(false);
    ESP.restart();
  }
}
