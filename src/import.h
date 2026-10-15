/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stddef.h>

#include "totp.h"

#define IMPORT_MAX_BYTES (1024 * 1024)
#define IMPORT_MAX_ENTRIES 500

struct import_stats {
  int added;
  int skipped_md5;
  int skipped_hotp;
  int invalid; /* lines or entries that could not be parsed */
};

/* Parses otpauth:// and otpauth-migration:// lines from untrusted text.
 * Appends up to `max` entries to `out`; returns the number added. */
int import_text(const char *text, size_t len, struct otp_entry *out, int max,
                struct import_stats *stats);
