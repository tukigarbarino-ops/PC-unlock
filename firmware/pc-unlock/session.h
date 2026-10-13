#pragma once
// Sesión de teclado / mouse / multimedia por la ESP (respaldo cuando PC Unlock Host no está disponible).
// Un Face ID abre la sesión (challenge "rs"/"rr" con la clave ECDH efímera de la app en "e"). La ESP:
//   1) genera su clave ECDH efímera y calcula el secreto compartido,
//   2) deriva la clave AES-256-GCM con HKDF-SHA256 (salt = nonce, info = "PCU-ESP-SESSION"),
//   3) firma {nonce, clave de la app, su clave efímera, vencimiento} con su CLAVE DE IDENTIDAD (fijada en la app
//      al emparejar comparando un código), así nadie en el broker puede cambiar la clave efímera y leer lo tipeado.
// Cada mensaje de entrada: seq (u32 LE) || AES-256-GCM(cifrado || tag 16), IV = "PCUI" || seq (u32 LE) || 0000.
// Este módulo no depende de Arduino: compila también en una PC para las pruebas.
#include <stdint.h>
#include <stddef.h>
#include <string>

namespace sess {

typedef int (*RngFn)(void* ctx, unsigned char* out, size_t len);

// ---- Identidad de la ESP (P-256)
bool identityGenerate(uint8_t priv[32], RngFn rng, void* ctx);
bool identityPublic(const uint8_t priv[32], uint8_t pub[65], RngFn rng, void* ctx);
// Código para comparar con la app: base32 (Crockford) de SHA256("PCU-ID|esp|" || pub), "XXXX-XXXX-XXXX-XXXX".
std::string verificationCode(const uint8_t pub[65]);
// Firma ECDSA P-256 / SHA-256 en formato r||s (64 B), el que usa WebCrypto.
bool sign(const uint8_t priv[32], const std::string& text, uint8_t sig[64], RngFn rng, void* ctx);

// ---- Sesión
struct Session {
  bool active = false;
  uint8_t key[32] = {0};
  uint32_t lastSeq = 0;
  int64_t exp = 0;
};

std::string sessionPayload(const std::string& nonce, const std::string& appPubB64, const std::string& espPubB64, int64_t exp);

// Abre la sesión con la clave pública ECDH de la app (65 B). Devuelve "" o un error.
std::string open(Session& s, const uint8_t appPub[65], const std::string& nonce, int64_t exp, uint8_t espPub[65],
                 RngFn rng, void* ctx);

// Descifra un mensaje. out tiene que tener lugar para len - 20 bytes.
// Devuelve el largo del texto plano, o -1 si es inválido, repetido o la sesión venció.
int decrypt(Session& s, const uint8_t* in, size_t len, uint8_t* out, int64_t now);

void close(Session& s);

}  // namespace sess
