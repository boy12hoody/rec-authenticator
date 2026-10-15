/* SPDX-License-Identifier: Apache-2.0 */
#include "totp.h"

#include <string.h>

#include "monocypher-ed25519.h"
#include "monocypher.h"

/* SHA-1 and SHA-256 share the 64-byte Merkle-Damgard framing. SHA-512 comes
 * from Monocypher. Inputs here are tiny, so the byte-wise update is fine. */
struct md {
  uint32_t h[8];
  uint8_t buf[64];
  uint64_t total;
  int words;
  void (*block)(uint32_t *h, const uint8_t *p);
};

static uint32_t rol(uint32_t x, int n) { return x << n | x >> (32 - n); }
static uint32_t ror(uint32_t x, int n) { return x >> n | x << (32 - n); }
static uint32_t be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void sha1_block(uint32_t *h, const uint8_t *p) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) w[i] = be32(p + 4 * i);
  for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) f = (b & c) | (~b & d), k = 0x5a827999;
    else if (i < 40) f = b ^ c ^ d, k = 0x6ed9eba1;
    else if (i < 60) f = (b & c) | (b & d) | (c & d), k = 0x8f1bbcdc;
    else f = b ^ c ^ d, k = 0xca62c1d6;
    uint32_t t = rol(a, 5) + f + e + k + w[i];
    e = d, d = c, c = rol(b, 30), b = a, a = t;
  }
  h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e;
  crypto_wipe(w, sizeof(w));
}

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void sha256_block(uint32_t *h, const uint8_t *p) {
  uint32_t w[64], s[8];
  for (int i = 0; i < 16; i++) w[i] = be32(p + 4 * i);
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  memcpy(s, h, sizeof(s));
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = s[7] + (ror(s[4], 6) ^ ror(s[4], 11) ^ ror(s[4], 25)) +
                  ((s[4] & s[5]) ^ (~s[4] & s[6])) + K256[i] + w[i];
    uint32_t t2 = (ror(s[0], 2) ^ ror(s[0], 13) ^ ror(s[0], 22)) +
                  ((s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]));
    memmove(s + 1, s, 7 * sizeof(uint32_t));
    s[4] += t1;
    s[0] = t1 + t2;
  }
  for (int i = 0; i < 8; i++) h[i] += s[i];
  crypto_wipe(w, sizeof(w));
  crypto_wipe(s, sizeof(s));
}

static void md_init(struct md *c, enum otp_algo algo) {
  static const uint32_t h1[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
  static const uint32_t h256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memset(c, 0, sizeof(*c));
  c->words = algo == OTP_SHA1 ? 5 : 8;
  c->block = algo == OTP_SHA1 ? sha1_block : sha256_block;
  memcpy(c->h, algo == OTP_SHA1 ? h1 : h256, c->words * sizeof(uint32_t));
}

static void md_update(struct md *c, const uint8_t *p, size_t n) {
  while (n--) {
    c->buf[c->total++ % 64] = *p++;
    if (c->total % 64 == 0) c->block(c->h, c->buf);
  }
}

static void md_final(struct md *c, uint8_t *out) {
  uint64_t bits = c->total * 8;
  uint8_t b = 0x80;
  md_update(c, &b, 1);
  b = 0;
  while (c->total % 64 != 56) md_update(c, &b, 1);
  for (int i = 7; i >= 0; i--) {
    b = (uint8_t)(bits >> (i * 8));
    md_update(c, &b, 1);
  }
  for (int i = 0; i < c->words; i++)
    for (int j = 0; j < 4; j++) out[4 * i + j] = (uint8_t)(c->h[i] >> (24 - 8 * j));
  crypto_wipe(c, sizeof(*c));
}

size_t otp_hmac(enum otp_algo algo, const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len, uint8_t *mac) {
  if (algo == OTP_SHA512) {
    crypto_sha512_hmac(mac, key, key_len, msg, msg_len);
    return 64;
  }
  const size_t out_len = algo == OTP_SHA1 ? 20 : 32;
  uint8_t k[64] = {0}, pad[64];
  struct md c;
  if (key_len > 64) {
    md_init(&c, algo);
    md_update(&c, key, key_len);
    md_final(&c, k);
  } else {
    memcpy(k, key, key_len);
  }
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
  md_init(&c, algo);
  md_update(&c, pad, 64);
  md_update(&c, msg, msg_len);
  md_final(&c, mac);
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
  md_init(&c, algo);
  md_update(&c, pad, 64);
  md_update(&c, mac, out_len);
  md_final(&c, mac);
  crypto_wipe(k, sizeof(k));
  crypto_wipe(pad, sizeof(pad));
  return out_len;
}

uint32_t hotp(enum otp_algo algo, const uint8_t *key, size_t key_len,
              uint64_t counter, int digits) {
  uint8_t msg[8], mac[64];
  for (int i = 0; i < 8; i++) msg[i] = (uint8_t)(counter >> (56 - 8 * i));
  const size_t len = otp_hmac(algo, key, key_len, msg, 8, mac);
  const int off = mac[len - 1] & 0x0f;
  const uint32_t bin = (uint32_t)(mac[off] & 0x7f) << 24 | (uint32_t)mac[off + 1] << 16 |
                       (uint32_t)mac[off + 2] << 8 | mac[off + 3];
  crypto_wipe(mac, sizeof(mac));
  uint32_t mod = 1;
  for (int i = 0; i < digits; i++) mod *= 10;
  return bin % mod;
}

uint32_t totp(const struct otp_entry *e, uint64_t unix_time) {
  return hotp((enum otp_algo)e->algo, e->secret, e->secret_len,
              unix_time / (e->period ? e->period : 30), e->digits);
}

int base32_decode(const char *in, size_t in_len, uint8_t *out, size_t cap) {
  uint32_t acc = 0;
  int bits = 0;
  size_t n = 0;
  for (size_t i = 0; i < in_len; i++) {
    const char c = in[i];
    int v;
    if (c == ' ' || c == '-' || c == '=') continue;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a';
    else if (c >= '2' && c <= '7') v = c - '2' + 26;
    else return -1;
    acc = acc << 5 | (uint32_t)v;
    bits += 5;
    if (bits >= 8) {
      if (n == cap) return -1;
      out[n++] = (uint8_t)(acc >> (bits - 8));
      bits -= 8;
    }
  }
  return (int)n;
}
