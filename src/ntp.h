/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define NTP_PACKET 48

/* SNTP client request. The transmit field carries a random nonce instead of
 * the device time, so the reply can be matched and the clock is not leaked. */
void ntp_request(uint8_t pkt[NTP_PACKET], const uint8_t nonce[8]);

/* Validates a server reply to nonce and computes server minus local time.
 * t1_ms/t4_ms: local Unix time in ms when the request was sent/reply came.
 * Returns 0 on success. */
int ntp_offset(const uint8_t *resp, size_t n, const uint8_t nonce[8], int64_t t1_ms,
               int64_t t4_ms, int64_t *offset_ms);
