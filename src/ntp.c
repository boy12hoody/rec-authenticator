/* SPDX-License-Identifier: Apache-2.0 */
#include "ntp.h"

#include <string.h>

#define NTP_UNIX_DELTA 2208988800LL /* 1900-01-01 to 1970-01-01 in seconds */

void ntp_request(uint8_t pkt[NTP_PACKET], const uint8_t nonce[8]) {
  memset(pkt, 0, NTP_PACKET);
  pkt[0] = 4 << 3 | 3; /* LI 0, version 4, mode 3 (client) */
  memcpy(pkt + 40, nonce, 8);
}

static uint32_t be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* NTP timestamp to Unix ms. Seconds below the 1970 mark belong to era 1
 * (from 2036), which keeps this right until 2104. */
static int64_t unix_ms(const uint8_t *p) {
  int64_t s = (int64_t)be32(p) - NTP_UNIX_DELTA;
  if (s < 0) s += 1LL << 32;
  return s * 1000 + (int64_t)(((uint64_t)be32(p + 4) * 1000) >> 32);
}

int ntp_offset(const uint8_t *resp, size_t n, const uint8_t nonce[8], int64_t t1_ms,
               int64_t t4_ms, int64_t *offset_ms) {
  if (n < NTP_PACKET) return -1;
  const int li = resp[0] >> 6, version = resp[0] >> 3 & 7, mode = resp[0] & 7;
  const int stratum = resp[1];
  if (li == 3 || version < 3 || version > 4 || mode != 4 || stratum < 1 || stratum > 15)
    return -1;
  if (memcmp(resp + 24, nonce, 8)) return -1; /* originate must echo our nonce */
  if (!be32(resp + 40)) return -1;
  const int64_t t2 = unix_ms(resp + 32), t3 = unix_ms(resp + 40);
  *offset_ms = ((t2 - t1_ms) + (t3 - t4_ms)) / 2;
  return 0;
}
