/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdint.h>

#include "totp.h"

#define VAULT_MAX 500

enum { VAULT_OK = 0, VAULT_IO = -1, VAULT_BAD_PIN = -2, VAULT_CORRUPT = -3 };

struct vault {
  struct otp_entry entries[VAULT_MAX];
  int count;
  uint8_t key[32];
  uint8_t salt[16];
  uint32_t kdf_kib, kdf_passes;
};

/* Argon2id cost for new vaults; tests lower it. Existing vaults keep theirs. */
extern uint32_t vault_kdf_kib;

int vault_create(struct vault *v, const char *pin);
/* New salt and key for pin; entries are kept. Call vault_save afterwards. */
int vault_rekey(struct vault *v, const char *pin);
int vault_open(struct vault *v, const char *path, const char *pin);
/* Re-derives with the stored salt; returns VAULT_OK when pin matches. */
int vault_check_pin(const struct vault *v, const char *pin);
int vault_save(const struct vault *v, const char *path);
void vault_wipe(struct vault *v);
