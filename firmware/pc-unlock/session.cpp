#include "session.h"

#include <string.h>
#include <mbedtls/version.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>

namespace sess {

static const char* CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static int sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
  return mbedtls_sha256(in, len, out, 0);
#else
  return mbedtls_sha256_ret(in, len, out, 0);
#endif
}

static int hmac(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]) {
  return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, klen, msg, mlen, out);
}

// Agrupa grupo + clave privada + punto para no repetir init/free.
struct Ec {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  Ec() {
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
  }
  ~Ec() {
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
  }
  bool load() { return mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0; }
};

bool identityGenerate(uint8_t priv[32], RngFn rng, void* ctx) {
  Ec e;
  return e.load() && mbedtls_ecp_gen_privkey(&e.grp, &e.d, rng, ctx) == 0 && mbedtls_mpi_write_binary(&e.d, priv, 32) == 0;
}

bool identityPublic(const uint8_t priv[32], uint8_t pub[65], RngFn rng, void* ctx) {
  Ec e;
  size_t olen = 0;
  return e.load() && mbedtls_mpi_read_binary(&e.d, priv, 32) == 0 && mbedtls_ecp_check_privkey(&e.grp, &e.d) == 0 &&
         mbedtls_ecp_mul(&e.grp, &e.Q, &e.d, &e.grp.G, rng, ctx) == 0 &&
         mbedtls_ecp_point_write_binary(&e.grp, &e.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65) == 0 && olen == 65;
}

std::string verificationCode(const uint8_t pub[65]) {
  static const char pre[] = "PCU-ID|esp|";
  uint8_t buf[sizeof(pre) - 1 + 65];
  memcpy(buf, pre, sizeof(pre) - 1);
  memcpy(buf + sizeof(pre) - 1, pub, 65);
  uint8_t h[32];
  sha256(buf, sizeof(buf), h);
  std::string out;
  uint32_t acc = 0;
  int bits = 0;
  for (int i = 0; i < 32 && out.size() < 16; i++) {
    acc = (acc << 8) | h[i];
    bits += 8;
    while (bits >= 5 && out.size() < 16) {
      bits -= 5;
      out.push_back(CROCKFORD[(acc >> bits) & 31]);
    }
  }
  return out.substr(0, 4) + "-" + out.substr(4, 4) + "-" + out.substr(8, 4) + "-" + out.substr(12, 4);
}

bool sign(const uint8_t priv[32], const std::string& text, uint8_t sig[64], RngFn rng, void* ctx) {
  Ec e;
  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  uint8_t hash[32];
  sha256((const uint8_t*)text.data(), text.size(), hash);
  bool ok = e.load() && mbedtls_mpi_read_binary(&e.d, priv, 32) == 0 &&
            mbedtls_ecdsa_sign(&e.grp, &r, &s, &e.d, hash, 32, rng, ctx) == 0 &&
            mbedtls_mpi_write_binary(&r, sig, 32) == 0 && mbedtls_mpi_write_binary(&s, sig + 32, 32) == 0;
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  return ok;
}

std::string sessionPayload(const std::string& nonce, const std::string& appPubB64, const std::string& espPubB64, int64_t exp) {
  return "PCU-ESP-SESSION|" + nonce + "|" + appPubB64 + "|" + espPubB64 + "|" + std::to_string((long long)exp);
}

std::string open(Session& s, const uint8_t appPub[65], const std::string& nonce, int64_t exp, uint8_t espPub[65],
                 RngFn rng, void* ctx) {
  close(s);
  Ec e;
  mbedtls_ecp_point peer;
  mbedtls_mpi z;
  mbedtls_ecp_point_init(&peer);
  mbedtls_mpi_init(&z);
  uint8_t shared[32];
  size_t olen = 0;
  std::string err;
  if (!e.load()) err = "ECC no disponible";
  else if (mbedtls_ecp_point_read_binary(&e.grp, &peer, appPub, 65) != 0 || mbedtls_ecp_check_pubkey(&e.grp, &peer) != 0)
    err = "Clave de sesión de la app inválida";
  else if (mbedtls_ecdh_gen_public(&e.grp, &e.d, &e.Q, rng, ctx) != 0 ||
           mbedtls_ecdh_compute_shared(&e.grp, &z, &peer, &e.d, rng, ctx) != 0 ||
           mbedtls_mpi_write_binary(&z, shared, 32) != 0 ||
           mbedtls_ecp_point_write_binary(&e.grp, &e.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, espPub, 65) != 0 || olen != 65)
    err = "No se pudo calcular la clave de sesión";
  mbedtls_mpi_free(&z);
  mbedtls_ecp_point_free(&peer);
  if (!err.empty()) return err;

  // HKDF-SHA256 (RFC 5869): PRK = HMAC(salt, Z); clave = HMAC(PRK, info || 0x01)
  uint8_t prk[32];
  static const char info[] = "PCU-ESP-SESSION";
  uint8_t t[sizeof(info)];
  memcpy(t, info, sizeof(info) - 1);
  t[sizeof(info) - 1] = 0x01;
  if (hmac((const uint8_t*)nonce.data(), nonce.size(), shared, 32, prk) != 0 || hmac(prk, 32, t, sizeof(t), s.key) != 0)
    return "No se pudo derivar la clave";
  memset(shared, 0, sizeof(shared));
  memset(prk, 0, sizeof(prk));
  s.lastSeq = 0;
  s.exp = exp;
  s.active = true;
  return "";
}

int decrypt(Session& s, const uint8_t* in, size_t len, uint8_t* out, int64_t now) {
  if (!s.active || len < 4 + 1 + 16 || len > 4 + 512 + 16) return -1;
  if (now > s.exp) { close(s); return -1; }
  uint32_t seq = (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
  if (seq <= s.lastSeq) return -1;  // repetido o viejo
  uint8_t iv[12] = {'P', 'C', 'U', 'I', in[0], in[1], in[2], in[3], 0, 0, 0, 0};
  size_t ctLen = len - 4 - 16;
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s.key, 256);
  if (rc == 0) rc = mbedtls_gcm_auth_decrypt(&gcm, ctLen, iv, sizeof(iv), nullptr, 0, in + 4 + ctLen, 16, in + 4, out);
  mbedtls_gcm_free(&gcm);
  if (rc != 0) return -1;
  s.lastSeq = seq;
  return (int)ctLen;
}

void close(Session& s) {
  memset(s.key, 0, sizeof(s.key));
  s.active = false;
  s.lastSeq = 0;
  s.exp = 0;
}

}  // namespace sess
