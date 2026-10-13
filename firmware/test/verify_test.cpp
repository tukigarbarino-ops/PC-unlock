// Prueba en PC del módulo auth: lee un código de emparejamiento y aserciones (JSON) y las verifica.
// Uso: verify_test <codigo> <archivo_mensajes.jsonl>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <ArduinoJson.h>
#include "../pc-unlock/auth.h"

int main(int argc, char** argv) {
  if (argc < 3) { fprintf(stderr, "uso: %s codigo mensajes.jsonl\n", argv[0]); return 2; }
  auth::Pairing p;
  std::string e = auth::parsePairCode(argv[1], p);
  if (!e.empty()) { printf("PAIR ERROR: %s\n", e.c_str()); return 1; }
  printf("pair ok: topic=%s rp=%s origin=%s host=%s user=%s port=%d\n", p.topic.c_str(), p.key.rpId.c_str(),
         p.key.origin.c_str(), p.mqttHost.c_str(), p.mqttUser.c_str(), p.mqttPort);
  std::ifstream f(argv[2]);
  std::string line;
  int fails = 0;
  while (std::getline(f, line)) {
    if (line.empty()) continue;
    JsonDocument d;
    deserializeJson(d, line);
    std::string expect = d["expect"] | "ok";
    auth::Command c;
    std::string err = auth::verifyAssertion(p.key, d["ad"] | "", d["cd"] | "", d["sig"] | "", c);
    bool ok = err.empty();
    bool pass = (expect == "ok") == ok;
    if (!pass) fails++;
    printf("[%s] expect=%s got=%s cmd=%s t=%lld n=%s\n", pass ? "PASS" : "FAIL", expect.c_str(),
           ok ? "ok" : err.c_str(), c.cmd.c_str(), (long long)c.t, c.nonce.c_str());
  }
  return fails ? 1 : 0;
}
