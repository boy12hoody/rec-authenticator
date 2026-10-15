/* SPDX-License-Identifier: Apache-2.0 */
/* libFuzzer harness for both importers. The first byte picks the mode:
 * odd = raw text lines, even = bytes wrapped as a migration payload so the
 * protobuf decoder sees arbitrary input past the base64 layer. */
#include <stdlib.h>
#include <string.h>

#include "../src/import.h"

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static struct otp_entry out[IMPORT_MAX_ENTRIES];
  struct import_stats stats = {0};
  if (!size) return 0;
  if (data[0] & 1) {
    import_text((const char *)data + 1, size - 1, out, IMPORT_MAX_ENTRIES, &stats);
    return 0;
  }
  static const char prefix[] = "otpauth-migration://offline?data=";
  char *text = malloc(sizeof(prefix) + size / 3 * 4 + 8);
  size_t n = sizeof(prefix) - 1;
  memcpy(text, prefix, n);
  for (size_t i = 1; i < size; i += 3) {
    uint32_t v = (uint32_t)data[i] << 16;
    if (i + 1 < size) v |= (uint32_t)data[i + 1] << 8;
    if (i + 2 < size) v |= data[i + 2];
    for (int k = 0; k < 4; k++) text[n++] = b64[(v >> (18 - 6 * k)) & 63];
  }
  import_text(text, n, out, IMPORT_MAX_ENTRIES, &stats);
  free(text);
  return 0;
}
