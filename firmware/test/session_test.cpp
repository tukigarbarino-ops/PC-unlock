// Prueba en PC de session.cpp (la sesión de teclado/mouse por la ESP), manejada por session_interop.mjs
// con WebCrypto (lo mismo que usa la web app). Protocolo por líneas en stdin/stdout:
//   id                       -> ID <pub b64url> <código de verificación>
//   open <appPub> <n> <exp>  -> OPEN <espPub b64url> <firma b64url>   |  ERR <msg>
//   frame <hex> <ahora>      -> OK <texto plano hex>                  |  ERR
//   close                    -> CLOSED
#include <cstdio>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include "../pc-unlock/auth.h"
#include "../pc-unlock/session.h"

static int rng(void*, unsigned char* out, size_t len) {
  static std::random_device rd;
  for (size_t i = 0; i < len; i++) out[i] = (unsigned char)rd();
  return 0;
}

static std::string hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s.push_back(d[p[i] >> 4]);
    s.push_back(d[p[i] & 15]);
  }
  return s;
}

int main() {
  uint8_t priv[32], pub[65];
  if (!sess::identityGenerate(priv, rng, nullptr) || !sess::identityPublic(priv, pub, rng, nullptr)) {
    printf("ERR identidad\n");
    return 1;
  }
  sess::Session s;
  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream in(line);
    std::string cmd;
    in >> cmd;
    if (cmd == "id") {
      printf("ID %s %s\n", auth::b64urlEncode(pub, 65).c_str(), sess::verificationCode(pub).c_str());
    } else if (cmd == "open") {
      std::string appB64, nonce;
      long long exp = 0;
      in >> appB64 >> nonce >> exp;
      std::vector<uint8_t> app;
      uint8_t esp[65], sig[64];
      if (!auth::b64urlDecode(appB64, app) || app.size() != 65) {
        printf("ERR clave app\n");
      } else {
        std::string err = sess::open(s, app.data(), nonce, exp, esp, rng, nullptr);
        std::string espB64 = auth::b64urlEncode(esp, 65);
        if (!err.empty()) printf("ERR %s\n", err.c_str());
        else if (!sess::sign(priv, sess::sessionPayload(nonce, appB64, espB64, exp), sig, rng, nullptr)) printf("ERR firma\n");
        else printf("OPEN %s %s\n", espB64.c_str(), auth::b64urlEncode(sig, 64).c_str());
      }
    } else if (cmd == "frame") {
      std::string h;
      long long now = 0;
      in >> h >> now;
      std::vector<uint8_t> b;
      for (size_t i = 0; i + 1 < h.size(); i += 2) b.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
      std::vector<uint8_t> out(b.size() + 1);
      int n = sess::decrypt(s, b.data(), b.size(), out.data(), now);
      if (n < 0) printf("ERR\n");
      else printf("OK %s\n", hex(out.data(), n).c_str());
    } else if (cmd == "close") {
      sess::close(s);
      printf("CLOSED\n");
    }
    fflush(stdout);
  }
  return 0;
}
