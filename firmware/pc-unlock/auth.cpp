#include "auth.h"

#include <string.h>
#include <ArduinoJson.h>
#include <mbedtls/version.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/asn1.h>

namespace auth {

static int sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
  return mbedtls_sha256(in, len, out, 0);
#else
  return mbedtls_sha256_ret(in, len, out, 0);
#endif
}

static int b64val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-' || c == '+') return 62;
  if (c == '_' || c == '/') return 63;
  return -1;
}

bool b64urlDecode(const std::string& in, std::vector<uint8_t>& out) {
  out.clear();
  out.reserve(in.size() * 3 / 4 + 3);
  uint32_t acc = 0;
  int bits = 0;
  for (char c : in) {
    if (c == '=') break;
    int v = b64val(c);
    if (v < 0) return false;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back((uint8_t)((acc >> bits) & 0xFF));
    }
  }
  return true;
}

std::string b64urlEncode(const uint8_t* data, size_t len) {
  static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve((len + 2) / 3 * 4);
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < len; i++) {
    acc = (acc << 8) | data[i];
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push_back(tbl[(acc >> bits) & 0x3F]);
    }
  }
  if (bits > 0) out.push_back(tbl[(acc << (6 - bits)) & 0x3F]);
  return out;
}

bool validPublicKey(const uint8_t pub[65]) {
  if (pub[0] != 0x04) return false;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
            mbedtls_ecp_point_read_binary(&grp, &Q, pub, 65) == 0 &&
            mbedtls_ecp_check_pubkey(&grp, &Q) == 0;
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

std::string parsePairCode(const std::string& codeIn, Pairing& out) {
  // Se toleran espacios o saltos de línea que se cuelen al copiar/pegar.
  std::string code;
  for (char c : codeIn)
    if (c != ' ' && c != '\n' && c != '\r' && c != '\t') code.push_back(c);
  if (code.rfind("PCU1.", 0) != 0) return "El código tiene que empezar con PCU1.";
  std::vector<uint8_t> json;
  if (!b64urlDecode(code.substr(5), json)) return "Código mal copiado (base64)";
  JsonDocument doc;
  if (deserializeJson(doc, (const char*)json.data(), json.size())) return "Código mal copiado (json)";
  const char* t = doc["t"];
  const char* r = doc["r"];
  const char* o = doc["o"];
  const char* k = doc["k"];
  const char* i = doc["i"];
  if (!t || !r || !o || !k || !i) return "Al código le faltan datos";
  if (strlen(t) < 8 || strlen(t) > 40) return "Tema MQTT inválido";
  for (const char* p = t; *p; p++)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))) return "Tema MQTT inválido";
  std::vector<uint8_t> pub;
  if (!b64urlDecode(k, pub) || pub.size() != 65) return "Clave pública inválida";
  memcpy(out.key.pub, pub.data(), 65);
  if (!validPublicKey(out.key.pub)) return "Clave pública inválida";
  out.topic = t;
  out.key.rpId = r;
  out.key.origin = o;
  out.key.credId = i;
  if (const char* h = doc["h"]) out.mqttHost = h;
  if (const char* u = doc["u"]) out.mqttUser = u;
  if (const char* w = doc["w"]) out.mqttPass = w;
  if (doc["p"].is<int>()) out.mqttPort = doc["p"].as<int>();
  return "";
}

// Firma DER (SEQUENCE { INTEGER r, INTEGER s }) -> r, s
static bool parseDerSig(const std::vector<uint8_t>& der, mbedtls_mpi* r, mbedtls_mpi* s) {
  unsigned char* p = (unsigned char*)der.data();
  const unsigned char* end = p + der.size();
  size_t len;
  if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) return false;
  if (p + len != end) return false;
  if (mbedtls_asn1_get_mpi(&p, end, r) != 0) return false;
  if (mbedtls_asn1_get_mpi(&p, end, s) != 0) return false;
  return p == end;
}

std::string verifyAssertion(const Key& key, const std::string& adB64, const std::string& cdB64,
                            const std::string& sigB64, Command& out) {
  std::vector<uint8_t> ad, cd, sig;
  if (!b64urlDecode(adB64, ad) || !b64urlDecode(cdB64, cd) || !b64urlDecode(sigB64, sig))
    return "Mensaje mal formado";
  if (ad.size() < 37) return "authenticatorData corto";
  if (cd.size() > 2048 || sig.size() > 80) return "Mensaje demasiado largo";

  // 1) clientDataJSON: tipo, origen y challenge (que contiene la orden).
  //    Se lee primero solo para poder responder con el nonce; nada se ejecuta si la firma falla.
  JsonDocument doc;
  if (deserializeJson(doc, (const char*)cd.data(), cd.size())) return "clientData inválido";
  const char* type = doc["type"];
  const char* origin = doc["origin"];
  const char* challenge = doc["challenge"];
  if (!type || strcmp(type, "webauthn.get") != 0) return "Tipo inválido";
  if (!origin || key.origin != origin) return "Origen inválido";
  if (!challenge) return "Falta challenge";

  std::vector<uint8_t> payload;
  if (!b64urlDecode(challenge, payload)) return "Challenge inválido";
  JsonDocument cmd;
  if (deserializeJson(cmd, (const char*)payload.data(), payload.size())) return "Orden inválida";
  const char* c = cmd["c"];
  const char* n = cmd["n"];
  if (!c || !n || !cmd["t"].is<int64_t>()) return "Orden incompleta";
  out.cmd = c;
  out.nonce = n;
  out.t = cmd["t"].as<int64_t>();
  if (const char* e = cmd["e"]) out.e = e;
  if (out.nonce.size() < 8 || out.nonce.size() > 64) return "Nonce inválido";

  // 2) authenticatorData: rpIdHash(32) | flags(1) | signCount(4)
  uint8_t rpHash[32];
  sha256((const uint8_t*)key.rpId.data(), key.rpId.size(), rpHash);
  if (memcmp(ad.data(), rpHash, 32) != 0) return "rpId distinto";
  uint8_t flags = ad[32];
  if (!(flags & 0x01)) return "Falta presencia del usuario";
  if (!(flags & 0x04)) return "Falta verificación (Face ID)";

  // 3) Firma: ECDSA-P256 sobre SHA256(authenticatorData || SHA256(clientDataJSON))
  uint8_t cdHash[32];
  sha256(cd.data(), cd.size(), cdHash);
  std::vector<uint8_t> signedData(ad);
  signedData.insert(signedData.end(), cdHash, cdHash + 32);
  uint8_t digest[32];
  sha256(signedData.data(), signedData.size(), digest);

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi r, s;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  std::string err;
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
      mbedtls_ecp_point_read_binary(&grp, &Q, key.pub, 65) != 0) {
    err = "Clave guardada inválida";
  } else if (!parseDerSig(sig, &r, &s)) {
    err = "Firma mal formada";
  } else if (mbedtls_ecdsa_verify(&grp, digest, 32, &Q, &r, &s) != 0) {
    err = "Firma inválida";
  }
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  if (!err.empty()) return err;

  return "";
}

}  // namespace auth
