#pragma once
// Verificación de órdenes firmadas con una passkey (WebAuthn, ES256 / P-256).
// Este módulo no depende de Arduino: compila también en una PC para los tests.
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

namespace auth {

bool b64urlDecode(const std::string& in, std::vector<uint8_t>& out);
std::string b64urlEncode(const uint8_t* data, size_t len);

// Datos de la passkey emparejada.
struct Key {
  std::string rpId;      // ej. "usuario.github.io"
  std::string origin;    // ej. "https://usuario.github.io"
  std::string credId;    // id de la credencial, base64url
  uint8_t pub[65];       // punto público P-256 sin comprimir (0x04 || X || Y)
};

// Contenido del "challenge" firmado: {"c":"unlock","t":1700000000,"n":"..."}
struct Command {
  std::string cmd;
  int64_t t = 0;
  std::string nonce;
};

// Datos del código de emparejamiento "PCU1.<base64url(json)>".
struct Pairing {
  std::string topic;
  Key key;
  // Datos del broker MQTT (opcionales en el código)
  std::string mqttHost, mqttUser, mqttPass;
  int mqttPort = 8883;
};

// Devuelve "" si todo está bien, o un mensaje de error.
std::string parsePairCode(const std::string& code, Pairing& out);

// Verifica una aserción WebAuthn y extrae la orden firmada.
// adB64 = authenticatorData, cdB64 = clientDataJSON, sigB64 = firma DER (todos base64url).
// Devuelve "" si la firma es válida, o un mensaje de error.
std::string verifyAssertion(const Key& key, const std::string& adB64, const std::string& cdB64,
                            const std::string& sigB64, Command& out);

// Chequeo de validez de un punto P-256.
bool validPublicKey(const uint8_t pub[65]);

}  // namespace auth
