/* SPDX-License-Identifier: Apache-2.0 */
#include "vault.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h>
#endif

#include "monocypher.h"

/* File: magic[8] | version u8 | kdf_kib u32le | kdf_passes u32le | salt[16] |
 * nonce[24] | ciphertext | mac[16]. The whole header is the AEAD's AD. */
#define MAGIC "AERATOTP"
#define VERSION 1
#define HEADER (8 + 1 + 4 + 4 + 16 + 24)
#define MAX_FILE (1024 * 1024)
#define ENTRY_MAX (5 + OTP_SECRET_MAX + 1 + OTP_ISSUER_MAX + 1 + OTP_NAME_MAX)
#define PLAIN_MAX (4 + VAULT_MAX * ENTRY_MAX)

uint32_t vault_kdf_kib = 64 * 1024;
static const uint32_t kdf_passes = 3;

static void put32(uint8_t *p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t get32(const uint8_t *p) {
  return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int derive(uint8_t key[32], const char *pin, const uint8_t salt[16], uint32_t kib,
                  uint32_t passes) {
  void *work = malloc((size_t)kib * 1024);
  if (!work) return VAULT_IO;
  crypto_argon2_config config = {CRYPTO_ARGON2_ID, kib, passes, 1};
  crypto_argon2_inputs inputs = {(const uint8_t *)pin, salt, (uint32_t)strlen(pin), 16};
  crypto_argon2(key, 32, work, config, inputs, crypto_argon2_no_extras);
  crypto_wipe(work, (size_t)kib * 1024);
  free(work);
  return VAULT_OK;
}

int vault_create(struct vault *v, const char *pin) {
  vault_wipe(v);
  return vault_rekey(v, pin);
}

int vault_rekey(struct vault *v, const char *pin) {
  v->kdf_kib = vault_kdf_kib;
  v->kdf_passes = kdf_passes;
  if (getentropy(v->salt, sizeof(v->salt))) return VAULT_IO;
  return derive(v->key, pin, v->salt, v->kdf_kib, v->kdf_passes);
}

int vault_check_pin(const struct vault *v, const char *pin) {
  uint8_t key[32];
  if (derive(key, pin, v->salt, v->kdf_kib, v->kdf_passes)) return VAULT_IO;
  const int same = crypto_verify32(key, v->key) == 0;
  crypto_wipe(key, sizeof(key));
  return same ? VAULT_OK : VAULT_BAD_PIN;
}

static size_t serialize(const struct vault *v, uint8_t *out) {
  uint8_t *p = out;
  put32(p, (uint32_t)v->count), p += 4;
  for (int i = 0; i < v->count; i++) {
    const struct otp_entry *e = &v->entries[i];
    const size_t il = strlen(e->issuer), nl = strlen(e->name);
    *p++ = e->algo, *p++ = e->digits;
    *p++ = (uint8_t)e->period, *p++ = (uint8_t)(e->period >> 8);
    *p++ = e->secret_len, memcpy(p, e->secret, e->secret_len), p += e->secret_len;
    *p++ = (uint8_t)il, memcpy(p, e->issuer, il), p += il;
    *p++ = (uint8_t)nl, memcpy(p, e->name, nl), p += nl;
  }
  return (size_t)(p - out);
}

static int take(const uint8_t **p, const uint8_t *end, void *dst, size_t n, size_t cap) {
  if (n > cap || (size_t)(end - *p) < n) return -1;
  memcpy(dst, *p, n);
  *p += n;
  return 0;
}

static int deserialize(struct vault *v, const uint8_t *p, size_t n) {
  const uint8_t *end = p + n;
  if (n < 4) return VAULT_CORRUPT;
  const uint32_t count = get32(p);
  p += 4;
  if (count > VAULT_MAX) return VAULT_CORRUPT;
  for (uint32_t i = 0; i < count; i++) {
    struct otp_entry *e = &v->entries[i];
    memset(e, 0, sizeof(*e));
    if (end - p < 5) return VAULT_CORRUPT;
    e->algo = p[0], e->digits = p[1], e->period = (uint16_t)(p[2] | p[3] << 8);
    e->secret_len = p[4];
    p += 5;
    uint8_t il, nl;
    if (e->algo > OTP_SHA512 || e->digits < 6 || e->digits > 8 || !e->period ||
        !e->secret_len || take(&p, end, e->secret, e->secret_len, sizeof(e->secret)) ||
        take(&p, end, &il, 1, 1) || take(&p, end, e->issuer, il, sizeof(e->issuer) - 1) ||
        take(&p, end, &nl, 1, 1) || take(&p, end, e->name, nl, sizeof(e->name) - 1))
      return VAULT_CORRUPT;
  }
  v->count = (int)count;
  return p == end ? VAULT_OK : VAULT_CORRUPT;
}

static int read_file(const char *path, uint8_t **data, size_t *len) {
  const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat st;
  if (fd < 0) return VAULT_IO;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > MAX_FILE) {
    close(fd);
    return VAULT_IO;
  }
  *data = malloc((size_t)st.st_size + 1);
  size_t done = 0;
  while (*data && done < (size_t)st.st_size) {
    const ssize_t r = read(fd, *data + done, (size_t)st.st_size - done);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) break;
    done += (size_t)r;
  }
  close(fd);
  if (!*data || done != (size_t)st.st_size) {
    free(*data);
    return VAULT_IO;
  }
  *len = done;
  return VAULT_OK;
}

int vault_open(struct vault *v, const char *path, const char *pin) {
  uint8_t *file = NULL, *plain = NULL;
  size_t len = 0;
  vault_wipe(v);
  if (read_file(path, &file, &len)) return VAULT_IO;
  int result = VAULT_CORRUPT;
  if (len < HEADER + 16 || memcmp(file, MAGIC, 8) || file[8] != VERSION) goto done;
  v->kdf_kib = get32(file + 9);
  v->kdf_passes = get32(file + 13);
  /* Bound attacker-chosen costs: 8 KiB..1 GiB, 1..16 passes. */
  if (v->kdf_kib < 8 || v->kdf_kib > 1024 * 1024 || !v->kdf_passes || v->kdf_passes > 16)
    goto done;
  memcpy(v->salt, file + 17, 16);
  const size_t text_len = len - HEADER - 16;
  if (!(plain = malloc(text_len + 1)) || derive(v->key, pin, v->salt, v->kdf_kib, v->kdf_passes)) {
    result = VAULT_IO;
    goto done;
  }
  if (crypto_aead_unlock(plain, file + len - 16, v->key, file + 33, file, HEADER,
                         file + HEADER, text_len)) {
    result = VAULT_BAD_PIN; /* or tampered; the two are indistinguishable */
    goto done;
  }
  result = deserialize(v, plain, text_len);
  crypto_wipe(plain, text_len);
done:
  free(plain);
  free(file);
  if (result != VAULT_OK) vault_wipe(v);
  return result;
}

static int write_all(int fd, const uint8_t *p, size_t n) {
  while (n) {
    const ssize_t w = write(fd, p, n);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) return -1;
    p += w, n -= (size_t)w;
  }
  return 0;
}

int vault_save(const struct vault *v, const char *path) {
  char tmp[512], dir[512];
  if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return VAULT_IO;
  uint8_t *buf = malloc(HEADER + PLAIN_MAX + 16);
  if (!buf) return VAULT_IO;
  uint8_t *plain = buf + HEADER; /* encrypted in place */
  memcpy(buf, MAGIC, 8);
  buf[8] = VERSION;
  put32(buf + 9, v->kdf_kib);
  put32(buf + 13, v->kdf_passes);
  memcpy(buf + 17, v->salt, 16);
  int result = VAULT_IO;
  if (getentropy(buf + 33, 24)) goto done;
  const size_t n = serialize(v, plain);
  crypto_aead_lock(plain, plain + n, v->key, buf + 33, buf, HEADER, plain, n);
  const int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) goto done;
  const int ok = !write_all(fd, buf, HEADER + n + 16) && !fsync(fd);
  close(fd);
  if (!ok || rename(tmp, path)) {
    unlink(tmp);
    goto done;
  }
  snprintf(dir, sizeof(dir), "%s", path);
  char *slash = strrchr(dir, '/');
  if (slash) {
    *slash = '\0';
    const int dfd = open(*dir ? dir : "/", O_RDONLY | O_CLOEXEC);
    if (dfd >= 0) fsync(dfd), close(dfd);
  }
  result = VAULT_OK;
done:
  crypto_wipe(buf, HEADER + PLAIN_MAX + 16);
  free(buf);
  return result;
}

void vault_wipe(struct vault *v) { crypto_wipe(v, sizeof(*v)); }
