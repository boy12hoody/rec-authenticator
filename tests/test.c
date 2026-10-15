/* SPDX-License-Identifier: Apache-2.0 */
/* Host unit tests: RFC vectors, importers, vault. Run with `make test`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/import.h"
#include "../src/ntp.h"
#include "../src/totp.h"
#include "../src/vault.h"

static int failures;
#define CHECK(cond)                                                   \
  do {                                                                \
    if (!(cond)) {                                                    \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
      failures++;                                                     \
    }                                                                 \
  } while (0)

static void hex(const char *s, uint8_t *out) {
  for (size_t i = 0; s[2 * i]; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
}

static void test_hotp_rfc4226(void) {
  /* RFC 4226 Appendix D. */
  static const uint32_t expect[10] = {755224, 287082, 359152, 969429, 338314,
                                      254676, 287922, 162583, 399871, 520489};
  const uint8_t *key = (const uint8_t *)"12345678901234567890";
  for (int i = 0; i < 10; i++) CHECK(hotp(OTP_SHA1, key, 20, (uint64_t)i, 6) == expect[i]);
}

static void test_totp_rfc6238(void) {
  /* RFC 6238 Appendix B, Table 1, with the seeds from its reference code. */
  static const struct {
    uint64_t t;
    uint32_t sha1, sha256, sha512;
  } v[] = {
      {59, 94287082, 46119246, 90693936},
      {1111111109, 7081804, 68084774, 25091201},
      {1111111111, 14050471, 67062674, 99943326},
      {1234567890, 89005924, 91819424, 93441116},
      {2000000000, 69279037, 90698825, 38618901},
      {20000000000ULL, 65353130, 77737706, 47863826},
  };
  const char *seed = "1234567890123456789012345678901234567890123456789012345678901234";
  struct otp_entry e = {.digits = 8, .period = 30};
  for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
    memcpy(e.secret, seed, 64);
    e.algo = OTP_SHA1, e.secret_len = 20;
    CHECK(totp(&e, v[i].t) == v[i].sha1);
    e.algo = OTP_SHA256, e.secret_len = 32;
    CHECK(totp(&e, v[i].t) == v[i].sha256);
    e.algo = OTP_SHA512, e.secret_len = 64;
    CHECK(totp(&e, v[i].t) == v[i].sha512);
  }
}

static void test_hmac_long_key(void) {
  /* Keys longer than the block size are hashed first (RFC 2202 #6, RFC 4231 #6). */
  uint8_t key[131], mac[64], want[64];
  memset(key, 0xaa, sizeof(key));
  const char *msg = "Test Using Larger Than Block-Size Key - Hash Key First";
  CHECK(otp_hmac(OTP_SHA1, key, 80, (const uint8_t *)msg, strlen(msg), mac) == 20);
  hex("aa4ae5e15272d00e95705637ce8a3b55ed402112", want);
  CHECK(!memcmp(mac, want, 20));
  CHECK(otp_hmac(OTP_SHA256, key, 131, (const uint8_t *)msg, strlen(msg), mac) == 32);
  hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", want);
  CHECK(!memcmp(mac, want, 32));
}

static void test_base32(void) {
  uint8_t out[32];
  /* "12345678901234567890" in canonical, lowercase+spaces, and padded forms. */
  CHECK(base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 32, out, sizeof(out)) == 20);
  CHECK(!memcmp(out, "12345678901234567890", 20));
  const char *loose = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
  CHECK(base32_decode(loose, strlen(loose), out, sizeof(out)) == 20);
  CHECK(!memcmp(out, "12345678901234567890", 20));
  CHECK(base32_decode("MZXW6===", 8, out, sizeof(out)) == 3 && !memcmp(out, "foo", 3));
  CHECK(base32_decode("MZXW6", 5, out, sizeof(out)) == 3);
  CHECK(base32_decode("MZ1W6", 5, out, sizeof(out)) == -1);
  CHECK(base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 32, out, 4) == -1);
}

static int parse(const char *text, struct otp_entry *out, struct import_stats *s) {
  memset(s, 0, sizeof(*s));
  return import_text(text, strlen(text), out, 8, s);
}

static void test_uri(void) {
  struct otp_entry e[8];
  struct import_stats s;
  CHECK(parse("otpauth://totp/ACME%20Co:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
              "&issuer=ACME+Co&algorithm=SHA256&digits=8&period=60\n",
              e, &s) == 1);
  CHECK(!strcmp(e[0].issuer, "ACME Co") && !strcmp(e[0].name, "john.doe@email.com"));
  CHECK(e[0].algo == OTP_SHA256 && e[0].digits == 8 && e[0].period == 60);
  CHECK(e[0].secret_len == 20);

  /* Issuer from the label when the parameter is missing; unicode survives. */
  CHECK(parse("  otpauth://totp/B%C3%BCro%3A%20j%C3%BCrgen?secret=MZXW6\r\n", e, &s) == 1);
  CHECK(!strcmp(e[0].issuer, "B\xc3\xbcro") && !strcmp(e[0].name, "j\xc3\xbcrgen"));
  CHECK(e[0].algo == OTP_SHA1 && e[0].digits == 6 && e[0].period == 30);

  /* Comments, blanks, and several lines. */
  CHECK(parse("# export\n\notpauth://totp/a?secret=MZXW6\notpauth://totp/b?secret=MZXW6\n", e,
              &s) == 2);

  /* Rejections. */
  const char *bad[] = {
      "otpauth://totp/x?secret=",           "otpauth://totp/x?issuer=a",
      "otpauth://totp/x",                   "otpauth://totp/x?secret=MZ1W6",
      "otpauth://totp/x?secret=MZXW6&digits=9", "otpauth://totp/x?secret=MZXW6&period=0",
      "otpauth://totp/x?secret=MZXW6&algorithm=SHA3", "otpauth://totp/%zz?secret=MZXW6",
      "otpauth://totp/x?secret=MZXW6%",     "https://example.com",
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    CHECK(parse(bad[i], e, &s) == 0);
    CHECK(s.invalid == 1);
  }
  CHECK(parse("otpauth://totp/x?secret=MZXW6&algorithm=MD5", e, &s) == 0 && s.skipped_md5 == 1);
  CHECK(parse("otpauth://hotp/x?secret=MZXW6&counter=1", e, &s) == 0 && s.skipped_hotp == 1);

  /* Control characters are neutralised; long labels truncate on a UTF-8 boundary. */
  CHECK(parse("otpauth://totp/a%0Ab?secret=MZXW6", e, &s) == 1 && !strcmp(e[0].name, "a b"));
  char line[600] = "otpauth://totp/";
  for (int i = 0; i < 60; i++) strcat(line, "%C3%BC");
  strcat(line, "?secret=MZXW6");
  CHECK(parse(line, e, &s) == 1);
  CHECK(strlen(e[0].name) == 94); /* 47 two-byte chars fit in 95 bytes */

  /* The entry cap holds. */
  struct otp_entry one[1];
  memset(&s, 0, sizeof(s));
  const char *two = "otpauth://totp/a?secret=MZXW6\notpauth://totp/b?secret=MZXW6\n";
  CHECK(import_text(two, strlen(two), one, 1, &s) == 1 && s.invalid == 1);
}

static void test_migration(void) {
  /* Generated by tests/make_migration.py: SHA1/6 Example, SHA256/8 unicode,
   * one MD5 entry and one HOTP entry. */
  const char *uri =
      "otpauth-migration://offline?data=CjgKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhFhbGljZUBleGFtcGxlLmNvbRoH"
      "RXhhbXBsZSABKAEwAgo5CiAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMhIPw5xuw69jw7hkw6k6Ym9iIAIo"
      "AjACChYKCW1kNXNlY3JldBIDbWQ1IAQoATACChsKCmhvdHBzZWNyZXQSB2NvdW50ZXIgASgBMAEQARgBIAAoKg%3D%3D";
  struct otp_entry e[8];
  struct import_stats s;
  CHECK(parse(uri, e, &s) == 2);
  CHECK(s.skipped_md5 == 1 && s.skipped_hotp == 1 && s.invalid == 0);
  CHECK(!strcmp(e[0].issuer, "Example") && !strcmp(e[0].name, "alice@example.com"));
  CHECK(e[0].algo == OTP_SHA1 && e[0].digits == 6 && e[0].secret_len == 20);
  CHECK(totp(&e[0], 59) == 287082);
  CHECK(!strcmp(e[1].issuer, "\xc3\x9c" "n" "\xc3\xaf" "c" "\xc3\xb8" "d" "\xc3\xa9"));
  CHECK(!strcmp(e[1].name, "bob"));
  CHECK(e[1].algo == OTP_SHA256 && e[1].digits == 8 && e[1].secret_len == 32);
  CHECK(totp(&e[1], 59) == 46119246);

  const char *bad[] = {
      "otpauth-migration://offline?data=",
      "otpauth-migration://offline?nodata=1",
      "otpauth-migration://offline?data=%%%",
      "otpauth-migration://offline?data=CgYKAzEyMw", /* truncated nested message */
      "otpauth-migration://offline?data=Cv____8P",   /* length far beyond input */
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    CHECK(parse(bad[i], e, &s) == 0);
    CHECK(s.invalid >= 1);
  }
  /* Empty secret inside an otherwise valid message: CgQSAmFh = {1:{2:"aa"}}. */
  CHECK(parse("otpauth-migration://offline?data=CgQSAmFh", e, &s) == 0 && s.invalid == 1);
}

static void test_vault(void) {
  static struct vault v, w;
  char path[] = "/tmp/aera-auth-test-XXXXXX";
  const int fd = mkstemp(path);
  CHECK(fd >= 0);
  close(fd);
  vault_kdf_kib = 1024; /* keep tests fast; production is 64 MiB */

  CHECK(vault_create(&v, "12345678") == VAULT_OK);
  struct import_stats s = {0};
  const char *text = "otpauth://totp/Ex:a?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8\n";
  v.count = import_text(text, strlen(text), v.entries, VAULT_MAX, &s);
  CHECK(v.count == 1);
  CHECK(vault_save(&v, path) == VAULT_OK);

  CHECK(vault_open(&w, path, "12345678") == VAULT_OK);
  CHECK(w.count == 1 && !strcmp(w.entries[0].issuer, "Ex") && !strcmp(w.entries[0].name, "a"));
  CHECK(totp(&w.entries[0], 59) == 94287082);
  CHECK(w.kdf_kib == 1024 && w.kdf_passes == 3);
  CHECK(vault_check_pin(&w, "12345678") == VAULT_OK);
  CHECK(vault_check_pin(&w, "12345679") == VAULT_BAD_PIN);

  CHECK(vault_open(&w, path, "87654321") == VAULT_BAD_PIN);
  CHECK(w.count == 0); /* wiped on failure */

  /* Any flipped byte (header included, it is AD) must fail authentication. */
  FILE *f = fopen(path, "r+b");
  fseek(f, 0, SEEK_END);
  const long size = ftell(f);
  for (long off = 9; off < size; off += 7) {
    int c;
    fseek(f, off, SEEK_SET);
    c = fgetc(f);
    fseek(f, off, SEEK_SET);
    fputc(c ^ 1, f);
    fflush(f);
    CHECK(vault_open(&w, path, "12345678") != VAULT_OK);
    fseek(f, off, SEEK_SET);
    fputc(c, f);
    fflush(f);
  }
  fclose(f);
  CHECK(vault_open(&w, path, "12345678") == VAULT_OK);

  /* Truncated or garbage files are rejected without crashing. */
  CHECK(truncate(path, 40) == 0);
  CHECK(vault_open(&w, path, "12345678") == VAULT_CORRUPT);
  CHECK(vault_open(&w, "/nonexistent/vault.bin", "12345678") == VAULT_IO);

  /* An empty vault round-trips too. */
  CHECK(vault_create(&v, "00000000") == VAULT_OK);
  CHECK(vault_save(&v, path) == VAULT_OK);
  CHECK(vault_open(&w, path, "00000000") == VAULT_OK && w.count == 0);
  unlink(path);
}

static void put_ntp(uint8_t *p, int64_t unix_ms) {
  const uint64_t sec = (uint64_t)(unix_ms / 1000 + 2208988800LL) & 0xffffffff;
  const uint64_t frac = (((uint64_t)(unix_ms % 1000) << 32) + 999) / 1000;
  for (int i = 0; i < 4; i++) p[i] = (uint8_t)(sec >> (24 - 8 * i));
  for (int i = 0; i < 4; i++) p[4 + i] = (uint8_t)(frac >> (24 - 8 * i));
}

static void test_ntp(void) {
  const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8}, other[8] = {9};
  uint8_t req[NTP_PACKET], resp[NTP_PACKET];
  ntp_request(req, nonce);
  CHECK(req[0] == 0x23 && !memcmp(req + 40, nonce, 8));
  /* Device 5 s behind, 50 ms each way; 2036-07 checks the era rollover too. */
  const int64_t bases[] = {1700000000000LL, 2100000000123LL};
  for (int i = 0; i < 2; i++) {
    const int64_t t1 = bases[i];
    int64_t off = 0;
    memset(resp, 0, sizeof(resp));
    resp[0] = 0x24, resp[1] = 1;
    memcpy(resp + 24, nonce, 8);
    put_ntp(resp + 32, t1 + 5050);
    put_ntp(resp + 40, t1 + 5060);
    CHECK(ntp_offset(resp, sizeof(resp), nonce, t1, t1 + 110, &off) == 0 && off == 5000);
  }
  int64_t off = 0;
  CHECK(ntp_offset(resp, sizeof(resp) - 1, nonce, 0, 0, &off));
  CHECK(ntp_offset(resp, sizeof(resp), other, 0, 0, &off));
  resp[1] = 0; /* kiss-of-death */
  CHECK(ntp_offset(resp, sizeof(resp), nonce, 0, 0, &off));
  resp[1] = 1, resp[0] = 0x23; /* client mode */
  CHECK(ntp_offset(resp, sizeof(resp), nonce, 0, 0, &off));
  resp[0] = 0xe4; /* unsynchronized */
  CHECK(ntp_offset(resp, sizeof(resp), nonce, 0, 0, &off));
}

int main(void) {
  test_hotp_rfc4226();
  test_totp_rfc6238();
  test_hmac_long_key();
  test_base32();
  test_uri();
  test_migration();
  test_vault();
  test_ntp();
  if (failures) {
    fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  puts("all tests passed");
  return 0;
}
