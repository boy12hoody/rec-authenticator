/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stddef.h>
#include <stdint.h>

enum otp_algo { OTP_SHA1, OTP_SHA256, OTP_SHA512 };

#define OTP_SECRET_MAX 128
#define OTP_ISSUER_MAX 64
#define OTP_NAME_MAX 96

struct otp_entry {
  char issuer[OTP_ISSUER_MAX];
  char name[OTP_NAME_MAX];
  uint8_t secret[OTP_SECRET_MAX];
  uint8_t secret_len;
  uint8_t algo;    /* enum otp_algo */
  uint8_t digits;  /* 6..8 */
  uint16_t period; /* seconds */
};

/* mac must hold 64 bytes; returns the MAC length. */
size_t otp_hmac(enum otp_algo algo, const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len, uint8_t *mac);
uint32_t hotp(enum otp_algo algo, const uint8_t *key, size_t key_len,
              uint64_t counter, int digits);
uint32_t totp(const struct otp_entry *entry, uint64_t unix_time);

/* Tolerates lowercase, spaces, dashes and missing padding.
 * Returns the decoded length or -1. */
int base32_decode(const char *in, size_t in_len, uint8_t *out, size_t cap);
