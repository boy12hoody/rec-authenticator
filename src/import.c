/* SPDX-License-Identifier: Apache-2.0 */
#include "import.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "monocypher.h"

enum { OK = 0, BAD = -1, MD5 = -2, HOTP = -3 };

/* Copies untrusted bytes into a NUL-terminated field: control bytes become
 * spaces and truncation never splits a UTF-8 sequence. */
static void set_str(char *dst, size_t cap, const char *src, size_t n) {
  if (n > cap - 1) {
    n = cap - 1;
    size_t start = n;
    while (start > 0 && ((uint8_t)src[start] & 0xc0) == 0x80) start--;
    n = start; /* drop the character that straddles the cut */
  }
  for (size_t i = 0; i < n; i++) {
    const uint8_t c = (uint8_t)src[i];
    dst[i] = c < 0x20 || c == 0x7f ? ' ' : (char)c;
  }
  dst[n] = '\0';
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Returns the decoded length, or -1 on a bad escape or if out is too small. */
static long pct_decode(const char *in, size_t n, char *out, size_t cap, int plus_space) {
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    char c = in[i];
    if (c == '%') {
      if (i + 2 >= n) return -1;
      const int hi = hexval(in[i + 1]), lo = hexval(in[i + 2]);
      if (hi < 0 || lo < 0) return -1;
      c = (char)(hi << 4 | lo);
      i += 2;
    } else if (c == '+' && plus_space) {
      c = ' ';
    }
    if (o == cap) return -1;
    out[o++] = c;
  }
  return (long)o;
}

static long b64_decode(const char *in, size_t n, uint8_t *out, size_t cap) {
  uint32_t acc = 0;
  int bits = 0;
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    const char c = in[i];
    int v;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if (c >= '0' && c <= '9') v = c - '0' + 52;
    else if (c == '+' || c == '-') v = 62;
    else if (c == '/' || c == '_') v = 63;
    else if (c == '=' || c == ' ') continue;
    else return -1;
    acc = acc << 6 | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      if (o == cap) return -1;
      out[o++] = (uint8_t)(acc >> (bits - 8));
      bits -= 8;
    }
  }
  return (long)o;
}

static void defaults(struct otp_entry *e) {
  memset(e, 0, sizeof(*e));
  e->algo = OTP_SHA1;
  e->digits = 6;
  e->period = 30;
}

/* Splits "Issuer:account"; a non-empty issuer field wins over the prefix. */
static void set_label(struct otp_entry *e, const char *label, size_t n) {
  const char *colon = memchr(label, ':', n);
  const char *name = label;
  size_t name_len = n;
  if (colon) {
    if (!e->issuer[0]) set_str(e->issuer, sizeof(e->issuer), label, (size_t)(colon - label));
    name = colon + 1;
    name_len = n - (size_t)(name - label);
  }
  while (name_len && *name == ' ') name++, name_len--;
  set_str(e->name, sizeof(e->name), name, name_len);
}

static int parse_uri_with(const char *line, size_t n, struct otp_entry *e, char *buf,
                          size_t cap) {
  static const char totp_prefix[] = "otpauth://totp/";
  static const char hotp_prefix[] = "otpauth://hotp/";
  const size_t plen = sizeof(totp_prefix) - 1;
  if (n >= plen && !strncasecmp(line, hotp_prefix, plen)) return HOTP;
  if (n < plen || strncasecmp(line, totp_prefix, plen)) return BAD;
  defaults(e);
  const char *label = line + plen, *end = line + n;
  const char *query = memchr(label, '?', (size_t)(end - label));
  if (!query) return BAD;
  char label_buf[512];
  const long label_len = pct_decode(label, (size_t)(query - label), label_buf,
                                    sizeof(label_buf), 0);
  if (label_len < 0) return BAD;
  int have_secret = 0, md5 = 0;
  for (const char *p = query + 1; p < end;) {
    const char *amp = memchr(p, '&', (size_t)(end - p));
    const char *stop = amp ? amp : end;
    const char *eq = memchr(p, '=', (size_t)(stop - p));
    if (eq) {
      const size_t klen = (size_t)(eq - p);
      const long vlen = pct_decode(eq + 1, (size_t)(stop - eq - 1), buf, cap, 1);
      if (vlen < 0) return BAD;
      if (klen == 6 && !strncasecmp(p, "secret", 6)) {
        const int len = base32_decode(buf, (size_t)vlen, e->secret, sizeof(e->secret));
        if (len <= 0) return BAD;
        e->secret_len = (uint8_t)len;
        have_secret = 1;
      } else if (klen == 6 && !strncasecmp(p, "issuer", 6)) {
        set_str(e->issuer, sizeof(e->issuer), buf, (size_t)vlen);
      } else if (klen == 9 && !strncasecmp(p, "algorithm", 9)) {
        if (vlen == 4 && !strncasecmp(buf, "SHA1", 4)) e->algo = OTP_SHA1;
        else if (vlen == 6 && !strncasecmp(buf, "SHA256", 6)) e->algo = OTP_SHA256;
        else if (vlen == 6 && !strncasecmp(buf, "SHA512", 6)) e->algo = OTP_SHA512;
        else if (vlen == 3 && !strncasecmp(buf, "MD5", 3)) md5 = 1;
        else return BAD;
      } else if (klen == 6 && !strncasecmp(p, "digits", 6)) {
        if (vlen != 1 || buf[0] < '6' || buf[0] > '8') return BAD;
        e->digits = (uint8_t)(buf[0] - '0');
      } else if (klen == 6 && !strncasecmp(p, "period", 6)) {
        unsigned period = 0;
        if (vlen < 1 || vlen > 3) return BAD;
        for (long i = 0; i < vlen; i++) {
          if (buf[i] < '0' || buf[i] > '9') return BAD;
          period = period * 10 + (unsigned)(buf[i] - '0');
        }
        if (period < 10 || period > 300) return BAD;
        e->period = (uint16_t)period;
      }
    }
    p = stop + 1;
  }
  if (md5) return MD5;
  if (!have_secret) return BAD;
  set_label(e, label_buf, (size_t)label_len);
  return OK;
}

static int parse_uri(const char *line, size_t n, struct otp_entry *e) {
  char buf[512];
  const int r = parse_uri_with(line, n, e, buf, sizeof(buf));
  crypto_wipe(buf, sizeof(buf));
  return r;
}

struct pb {
  const uint8_t *p, *end;
};

static int pb_varint(struct pb *b, uint64_t *v) {
  uint64_t r = 0;
  for (int shift = 0; shift < 64; shift += 7) {
    if (b->p >= b->end) return -1;
    const uint8_t c = *b->p++;
    r |= (uint64_t)(c & 0x7f) << shift;
    if (!(c & 0x80)) {
      *v = r;
      return 0;
    }
  }
  return -1;
}

/* Reads one field. Varints land in *v; length-delimited fields in data/len. */
static int pb_field(struct pb *b, uint64_t *field, uint64_t *v, const uint8_t **data,
                    size_t *len) {
  uint64_t tag;
  if (pb_varint(b, &tag)) return -1;
  *field = tag >> 3;
  *data = NULL;
  *len = 0;
  *v = 0;
  switch (tag & 7) {
    case 0: return pb_varint(b, v);
    case 1:
      if (b->end - b->p < 8) return -1;
      b->p += 8;
      return 0;
    case 5:
      if (b->end - b->p < 4) return -1;
      b->p += 4;
      return 0;
    case 2:
      if (pb_varint(b, v) || *v > (uint64_t)(b->end - b->p)) return -1;
      *data = b->p;
      *len = (size_t)*v;
      b->p += *len;
      return 0;
    default: return -1;
  }
}

static int parse_otp_parameters(const uint8_t *p, size_t n, struct otp_entry *e) {
  struct pb b = {p, p + n};
  uint64_t field, v;
  const uint8_t *data;
  size_t len;
  const uint8_t *name = NULL;
  size_t name_len = 0;
  uint64_t algo = 0, digits = 0, type = 0;
  defaults(e);
  while (b.p < b.end) {
    if (pb_field(&b, &field, &v, &data, &len)) return BAD;
    if (field == 1 && data) {
      if (len == 0 || len > sizeof(e->secret)) return BAD;
      memcpy(e->secret, data, len);
      e->secret_len = (uint8_t)len;
    } else if (field == 2 && data) {
      name = data, name_len = len;
    } else if (field == 3 && data) {
      set_str(e->issuer, sizeof(e->issuer), (const char *)data, len);
    } else if (field == 4 && !data) {
      algo = v;
    } else if (field == 5 && !data) {
      digits = v;
    } else if (field == 6 && !data) {
      type = v;
    }
  }
  if (type == 1) return HOTP;
  if (algo == 4) return MD5;
  if (!e->secret_len || algo > 3 || digits > 2 || type > 2) return BAD;
  e->algo = algo == 2 ? OTP_SHA256 : algo == 3 ? OTP_SHA512 : OTP_SHA1;
  e->digits = digits == 2 ? 8 : 6;
  if (name) {
    /* Google often stores "Issuer:account" in name; drop the duplicate. */
    const size_t ilen = strlen(e->issuer);
    if (ilen && name_len > ilen && !memcmp(name, e->issuer, ilen) && name[ilen] == ':') {
      name += ilen + 1, name_len -= ilen + 1;
      while (name_len && *name == ' ') name++, name_len--;
    }
    set_label(e, (const char *)name, name_len);
  }
  return OK;
}

static void tally(int result, struct import_stats *s) {
  if (result == MD5) s->skipped_md5++;
  else if (result == HOTP) s->skipped_hotp++;
  else if (result == BAD) s->invalid++;
}

static int parse_migration(const char *line, size_t n, struct otp_entry *out, int max,
                           struct import_stats *s) {
  static const char prefix[] = "otpauth-migration://offline?";
  const size_t plen = sizeof(prefix) - 1;
  const char *end = line + n, *data = NULL;
  size_t data_len = 0;
  for (const char *p = line + plen; p < end;) {
    const char *amp = memchr(p, '&', (size_t)(end - p));
    const char *stop = amp ? amp : end;
    if (stop - p >= 5 && !memcmp(p, "data=", 5)) data = p + 5, data_len = (size_t)(stop - p - 5);
    p = stop + 1;
  }
  if (!data) return BAD;
  char *text = malloc(data_len + 1);
  uint8_t *raw = malloc(data_len + 1);
  int added = 0, result = OK;
  long text_len, raw_len;
  if (!text || !raw || (text_len = pct_decode(data, data_len, text, data_len, 0)) < 0 ||
      (raw_len = b64_decode(text, (size_t)text_len, raw, data_len)) <= 0) {
    result = BAD;
    goto done;
  }
  struct pb b = {raw, raw + raw_len};
  while (b.p < b.end) {
    uint64_t field, v;
    const uint8_t *msg;
    size_t len;
    if (pb_field(&b, &field, &v, &msg, &len)) {
      s->invalid++;
      break;
    }
    if (field != 1 || !msg) continue;
    if (added == max) {
      s->invalid++;
      continue;
    }
    const int r = parse_otp_parameters(msg, len, &out[added]);
    if (r == OK) added++;
    else crypto_wipe(&out[added], sizeof(out[added])), tally(r, s);
  }
done:
  if (text) crypto_wipe(text, data_len + 1), free(text);
  if (raw) crypto_wipe(raw, data_len + 1), free(raw);
  return result == OK ? added : result;
}

int import_text(const char *text, size_t len, struct otp_entry *out, int max,
                struct import_stats *s) {
  static const char migration[] = "otpauth-migration://offline?";
  int added = 0;
  if (len > IMPORT_MAX_BYTES) {
    s->invalid++;
    return 0;
  }
  if (len >= 3 && !memcmp(text, "\xef\xbb\xbf", 3)) text += 3, len -= 3;
  for (size_t pos = 0; pos < len;) {
    const char *nl = memchr(text + pos, '\n', len - pos);
    size_t a = pos, b = nl ? (size_t)(nl - text) : len;
    pos = b + 1;
    while (a < b && (text[a] == ' ' || text[a] == '\t' || text[a] == '\r')) a++;
    while (b > a && (text[b - 1] == ' ' || text[b - 1] == '\t' || text[b - 1] == '\r')) b--;
    if (a == b || text[a] == '#') continue;
    const char *line = text + a;
    const size_t n = b - a;
    if (n >= sizeof(migration) - 1 && !strncasecmp(line, migration, sizeof(migration) - 1)) {
      const int r = parse_migration(line, n, out + added, max - added, s);
      if (r >= 0) added += r;
      else tally(r, s);
    } else if (added == max) {
      s->invalid++;
    } else {
      const int r = parse_uri(line, n, &out[added]);
      if (r == OK) added++;
      else crypto_wipe(&out[added], sizeof(out[added])), tally(r, s);
    }
  }
  s->added += added;
  return added;
}
