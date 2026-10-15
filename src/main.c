/* SPDX-License-Identifier: Apache-2.0 */
/* AERA Host API 2 worker: protocol loop and declarative screens. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/mman.h>
#include <sys/prctl.h>
#endif
#ifdef __APPLE__
#include <sys/random.h>
#endif

#include "import.h"
#include "monocypher.h"
#include "ntp.h"
#include "totp.h"
#include "vault.h"

/* Wire contract: recovery aeraui/features/plugin_api/protocol.hpp. */
#define AERA_MAGIC 0x41325049U
#define AERA_API 2U
enum kind {
  HELLO = 1, BEGIN_PAGE, ADD_BUTTON, COMMIT_PAGE, SET_STATUS, REQUEST_OPERATION,
  CLOSE_WORKER, ADD_SECTION, ADD_METRIC, UPDATE_METRIC, SET_BACK_ACTION,
  HELLO_ACK = 64, ACTION, LIFECYCLE, OPERATION_RESULT
};
enum {
  PRIMARY = 1, DESTRUCTIVE = 2, DISABLED = 4,
  METRIC_GOOD = 1 << 8, METRIC_WARNING = 1 << 9, METRIC_CRITICAL = 1 << 10, METRIC_ACCENT = 1 << 11
};
enum { FEATURE_METRICS = 1, FEATURE_BACK = 2 };
enum { RESUME = 1, STOP = 3 };

struct message {
  uint32_t magic, version, kind, request_id, value, flags;
  char title[96];
  char text[1024];
};
_Static_assert(sizeof(struct message) == 1144, "AERA packet size");

enum action {
  A_IMPORT = 1, A_SETTINGS, A_LOCK, A_PREV, A_NEXT, A_BACK, A_CHANGE_PIN, A_DELETE_LIST,
  A_CONFIRM, A_CANCEL, A_DELETE_FILE, A_KEEP_FILE, A_RETRY, A_CHECK_TIME,
  A_DIGIT = 100, A_ERASE = 110, A_OK = 111, A_FILE = 200, A_ACCOUNT = 300
};
enum screen {
  S_NONE, S_STORAGE, S_PIN, S_CODES, S_IMPORT, S_PREVIEW, S_IMPORTED, S_SETTINGS,
  S_DELETE_LIST, S_DELETE_CONFIRM
};
enum pin_mode { P_CREATE, P_CONFIRM, P_UNLOCK, P_CHANGE_OLD, P_CHANGE_NEW, P_CHANGE_CONFIRM };

#define PIN_MIN 8
#define PIN_MAX 32
#define CODES_PER_PAGE 15 /* one section header each; the host allows 16 */
#define PREVIEW_ROWS 30
#define ACCOUNTS_PER_PAGE 9
#define MAX_FILES 10
#define IDLE_LOCK_SECONDS 300
#define ROW_UTC 1
#define ROW_NTP 10
#define NTP_WAIT_MS 2000
#define ROW_CODE 1000

static const int fd = 4;
static uint32_t host_features;
static enum screen screen;
static enum pin_mode pin_mode;
static struct vault vault;
static int unlocked, page, delete_index;
static char pin[PIN_MAX + 1], first_pin[PIN_MAX + 1];
static struct otp_entry pending[IMPORT_MAX_ENTRIES];
static int pending_count, pending_dupes;
static struct import_stats pending_stats;
static char files[MAX_FILES][96], chosen_file[96];
static int file_count, more_files;
static char file_buf[IMPORT_MAX_BYTES + 1];
static char dir[256], vault_path[320], import_dir[320];
static uint64_t last_input_ms;

/* Network time check. IP literals because recovery has no resolv.conf. */
static const char *const ntp_servers[] = {
    "216.239.35.0",  /* time.google.com */
    "162.159.200.1", /* time.cloudflare.com */
    "216.239.35.4",  /* time.google.com */
};
#define NTP_SERVERS (int)(sizeof(ntp_servers) / sizeof(ntp_servers[0]))
static enum { NTP_IDLE, NTP_WAIT, NTP_DONE, NTP_FAIL, NTP_OFFLINE } ntp_state;
static int ntp_fd = -1, ntp_server, ntp_test_port, ntp_sent_any;
static uint8_t ntp_nonce[8];
static int64_t ntp_sent_ms, ntp_offset_ms;
static uint64_t ntp_deadline;

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void wipe_all(void) {
  vault_wipe(&vault);
  crypto_wipe(pending, sizeof(pending));
  crypto_wipe(file_buf, sizeof(file_buf));
  crypto_wipe(pin, sizeof(pin));
  crypto_wipe(first_pin, sizeof(first_pin));
  unlocked = 0;
}

static void die(void) {
  wipe_all();
  _exit(0);
}

/* Truncates without splitting a UTF-8 sequence. */
static void copy_text(char *dst, size_t cap, const char *src) {
  size_t n = strlen(src);
  if (n >= cap) {
    n = cap - 1;
    while (n && ((unsigned char)src[n] & 0xc0) == 0x80) n--;
  }
  memcpy(dst, src, n);
  dst[n] = '\0';
}

static void sendm(uint32_t kind, uint32_t id, uint32_t value, uint32_t flags,
                  const char *title, const char *text) {
  /* Sliding window of 100 msg/s under the host's 128/s kill switch. Host-side
   * batching could still bunch packets; lower it if that shows up. */
  static uint64_t sent[100];
  static unsigned head;
  const uint64_t oldest = sent[head % 100], now = now_ms();
  if (oldest && now - oldest < 1000) usleep((useconds_t)(1000 - (now - oldest)) * 1000);
  sent[head++ % 100] = now_ms();

  struct message m = {AERA_MAGIC, AERA_API, kind, id, value, flags, {0}, {0}};
  if (title) copy_text(m.title, sizeof(m.title), title);
  if (text) copy_text(m.text, sizeof(m.text), text);
  ssize_t n;
  do n = send(fd, &m, sizeof(m), MSG_NOSIGNAL);
  while (n < 0 && errno == EINTR);
  if (n != (ssize_t)sizeof(m)) die();
}

static void status(const char *fmt, ...) {
  char text[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(text, sizeof(text), fmt, ap);
  va_end(ap);
  sendm(SET_STATUS, 0, 0, 0, NULL, text);
}

static void begin(const char *title, const char *body) { sendm(BEGIN_PAGE, 0, 0, 0, title, body); }
static void button(uint32_t id, uint32_t flags, const char *title, const char *detail) {
  sendm(ADD_BUTTON, id, 0, flags, title, detail);
}
static void metric(uint32_t id, uint32_t flags, const char *title, const char *value) {
  sendm(ADD_METRIC, id, 0, flags, title, value);
}
static void section(const char *title) { sendm(ADD_SECTION, 0, 0, 0, title, NULL); }
static void commit(uint32_t back) {
  if (back && (host_features & FEATURE_BACK)) sendm(SET_BACK_ACTION, back, 0, 0, NULL, NULL);
  sendm(COMMIT_PAGE, 0, 0, 0, NULL, NULL);
}

static void utc_now(char *out, size_t cap) {
  const time_t t = time(NULL);
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(out, cap, "%Y-%m-%d %H:%M:%S UTC", &tm);
}

static int64_t unix_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Network time row: server minus device time, tinted by how far off it is.
 * The host sizes a row when the page renders and does not re-measure it on
 * UPDATE_METRIC, so every text here must stay on one line. */
static uint32_t ntp_text(char *out, size_t cap) {
  const int64_t off = ntp_offset_ms < 0 ? -ntp_offset_ms : ntp_offset_ms;
  const char *dir = ntp_offset_ms > 0 ? "behind" : "ahead";
  switch (ntp_state) {
    case NTP_IDLE:
    case NTP_WAIT: snprintf(out, cap, "Checking"); return 0;
    case NTP_OFFLINE: snprintf(out, cap, "No network"); return METRIC_WARNING;
    case NTP_FAIL: snprintf(out, cap, "No reply"); return METRIC_WARNING;
    case NTP_DONE: break;
  }
  if (off < 1000) snprintf(out, cap, "Matches");
  else if (off < 100000)
    snprintf(out, cap, "%lld.%lld s %s", (long long)(off / 1000), (long long)(off % 1000 / 100), dir);
  else snprintf(out, cap, "%lld min %s", (long long)(off / 60000), dir);
  return off >= 15000 ? METRIC_CRITICAL : off >= 3000 ? METRIC_WARNING : METRIC_GOOD;
}

static void ntp_metric(void) {
  char text[128];
  const uint32_t flags = ntp_text(text, sizeof(text));
  metric(ROW_NTP, flags, "Network time", text);
}

static void ntp_update_row(void) {
  char text[128];
  if (screen != S_CODES && screen != S_SETTINGS) return;
  const uint32_t flags = ntp_text(text, sizeof(text));
  sendm(UPDATE_METRIC, ROW_NTP, 0, flags, NULL, text);
}

static void ntp_close(void) {
  if (ntp_fd >= 0) close(ntp_fd);
  ntp_fd = -1;
}

/* Sends one SNTP request, moving down the server list past local errors. */
static void ntp_send(void) {
  uint8_t pkt[NTP_PACKET];
  ntp_close();
  for (; ntp_server < NTP_SERVERS; ntp_server++) {
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(123)};
    inet_pton(AF_INET, ntp_test_port ? "127.0.0.1" : ntp_servers[ntp_server], &addr.sin_addr);
    if (ntp_test_port) addr.sin_port = htons((uint16_t)ntp_test_port);
    if (getentropy(ntp_nonce, sizeof(ntp_nonce))) break;
    ntp_request(pkt, ntp_nonce);
    ntp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ntp_fd < 0) break;
    fcntl(ntp_fd, F_SETFD, FD_CLOEXEC);
    fcntl(ntp_fd, F_SETFL, O_NONBLOCK);
    ntp_sent_ms = unix_ms();
    if (!connect(ntp_fd, (struct sockaddr *)&addr, sizeof(addr)) &&
        send(ntp_fd, pkt, sizeof(pkt), 0) == (ssize_t)sizeof(pkt)) {
      ntp_state = NTP_WAIT;
      ntp_sent_any = 1;
      ntp_deadline = now_ms() + NTP_WAIT_MS;
      return;
    }
    ntp_close();
  }
  ntp_close();
  ntp_state = ntp_sent_any ? NTP_FAIL : NTP_OFFLINE; /* no route to any server */
  ntp_update_row();
}

static void ntp_start(void) {
  ntp_server = 0;
  ntp_sent_any = 0;
  ntp_state = NTP_WAIT;
  ntp_update_row();
  ntp_send();
}

/* Called when the socket is readable or the wait ran out. */
static void ntp_poll(void) {
  uint8_t resp[128];
  const ssize_t n = recv(ntp_fd, resp, sizeof(resp), 0);
  if (n > 0 && !ntp_offset(resp, (size_t)n, ntp_nonce, ntp_sent_ms, unix_ms(), &ntp_offset_ms)) {
    ntp_close();
    ntp_state = NTP_DONE;
    ntp_update_row();
    return;
  }
  /* A forged or stray reply does not end the wait; an ICMP error does. */
  if ((n >= 0 || errno == EAGAIN || errno == EWOULDBLOCK) && now_ms() < ntp_deadline) return;
  ntp_server++;
  ntp_send();
}

static void entry_label(const struct otp_entry *e, char *out, size_t cap) {
  if (e->issuer[0] && e->name[0]) snprintf(out, cap, "%s: %s", e->issuer, e->name);
  else snprintf(out, cap, "%s", e->issuer[0] ? e->issuer : e->name[0] ? e->name : "(unnamed)");
}

static void format_code(uint32_t code, int digits, char *out, size_t cap) {
  char d[9];
  snprintf(d, sizeof(d), "%0*u", digits, code);
  const int split = digits == 8 ? 4 : 3;
  snprintf(out, cap, "%.*s %s", split, d, d + split);
}

/* "123 456   12 s", plus the next code during the last 10 seconds. */
static uint32_t code_text(const struct otp_entry *e, char *out, size_t cap) {
  const uint64_t t = (uint64_t)time(NULL);
  const unsigned remaining = e->period - (unsigned)(t % e->period);
  char now[16], next[16];
  format_code(totp(e, t), e->digits, now, sizeof(now));
  if (remaining <= 10) {
    format_code(totp(e, t + e->period), e->digits, next, sizeof(next));
    snprintf(out, cap, "%s  %u s  next %s", now, remaining, next); /* one line, see ntp_text */
  } else {
    snprintf(out, cap, "%s   %u s", now, remaining);
  }
  return remaining <= 5 ? METRIC_WARNING : 0;
}

/* ---- screens ---- */

static void pin_status(void) {
  char stars[PIN_MAX * 2 + 1] = "";
  for (size_t i = 0; i < strlen(pin); i++) strcat(stars, "* ");
  if (pin[0]) status("PIN: %s(%zu digits)", stars, strlen(pin));
  else status("Enter your PIN with the buttons above");
}

static void show_pin(enum pin_mode mode) {
  static const char *const titles[] = {"Create a PIN", "Confirm PIN", "Unlock",
                                       "Change PIN", "New PIN", "Confirm new PIN"};
  static const char *const bodies[] = {
      "Choose a PIN of at least 8 digits. It encrypts your vault, and a forgotten PIN "
      "cannot be recovered. Use 10 or more digits: anyone who copies the vault file "
      "can try PINs offline.",
      "Enter the same PIN again.",
      "Enter your PIN to open the vault.",
      "Enter your current PIN.",
      "Choose a new PIN of at least 8 digits. 10 or more is safer.",
      "Enter the new PIN again.",
  };
  const int changing = mode >= P_CHANGE_OLD;
  screen = S_PIN;
  pin_mode = mode;
  crypto_wipe(pin, sizeof(pin));
  begin(titles[mode], bodies[mode]);
  static const char *const digits[] = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"};
  for (int i = 0; i < 10; i++) button(A_DIGIT + (uint32_t)(i == 9 ? 0 : i + 1), 0, digits[i], NULL);
  button(A_ERASE, DESTRUCTIVE, "Delete", changing ? "Tap twice to clear; when empty, cancel"
                                        : "Remove the last digit. Tap twice to clear");
  button(A_OK, PRIMARY, "OK", NULL);
  commit(0);
  pin_status();
}

static void show_codes(void) {
  char label[96], value[96], utc[48];
  const int pages = vault.count ? (vault.count + CODES_PER_PAGE - 1) / CODES_PER_PAGE : 1;
  if (page >= pages) page = pages - 1;
  screen = S_CODES;
  begin("Rec Authenticator", vault.count ? "" : "No accounts yet. Choose Import to add some.");
  utc_now(utc, sizeof(utc));
  metric(ROW_UTC, METRIC_ACCENT, "Device time", utc);
  ntp_metric();
  const int first = page * CODES_PER_PAGE;
  for (int i = first; i < vault.count && i < first + CODES_PER_PAGE; i++) {
    /* Two lines per account: the name as a section header, then the code. */
    entry_label(&vault.entries[i], label, sizeof(label));
    section(label);
    const uint32_t flags = code_text(&vault.entries[i], value, sizeof(value));
    metric(ROW_CODE + (uint32_t)i, flags, " ", value);
  }
  crypto_wipe(value, sizeof(value));
  if (page > 0) button(A_PREV, 0, "Previous page", NULL);
  if (page + 1 < pages) button(A_NEXT, 0, "Next page", NULL);
  button(A_IMPORT, vault.count ? 0 : PRIMARY, "Import accounts", "From a .txt file on internal storage");
  button(A_SETTINGS, 0, "Settings", "PIN, accounts, device time");
  button(A_LOCK, 0, "Lock", NULL);
  commit(0);
  if (pages > 1) status("Page %d of %d, %d accounts", page + 1, pages, vault.count);
}

static void tick(void) {
  char value[96], utc[48];
  if (unlocked && now_ms() - last_input_ms > IDLE_LOCK_SECONDS * 1000ULL) {
    wipe_all();
    show_pin(P_UNLOCK);
    status("Locked after %d minutes without input", IDLE_LOCK_SECONDS / 60);
    return;
  }
  if (screen != S_CODES && screen != S_SETTINGS) return;
  utc_now(utc, sizeof(utc));
  sendm(UPDATE_METRIC, ROW_UTC, 0, METRIC_ACCENT, NULL, utc);
  if (screen != S_CODES) return;
  const int first = page * CODES_PER_PAGE;
  for (int i = first; i < vault.count && i < first + CODES_PER_PAGE; i++) {
    const uint32_t flags = code_text(&vault.entries[i], value, sizeof(value));
    sendm(UPDATE_METRIC, ROW_CODE + (uint32_t)i, 0, flags, NULL, value);
  }
  crypto_wipe(value, sizeof(value));
}

static int has_suffix(const char *s, const char *suffix) {
  const size_t n = strlen(s), m = strlen(suffix);
  return n >= m && !strcasecmp(s + n - m, suffix);
}

static int compare_names(const void *a, const void *b) { return strcmp(a, b); }

static void scan_files(void) {
  file_count = more_files = 0;
  DIR *d = opendir(import_dir);
  if (!d) return;
  struct dirent *ent;
  while ((ent = readdir(d))) {
    struct stat st;
    if (strlen(ent->d_name) >= sizeof(files[0]) || !has_suffix(ent->d_name, ".txt") ||
        fstatat(dirfd(d), ent->d_name, &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode))
      continue;
    if (file_count == MAX_FILES) {
      more_files = 1;
      continue;
    }
    snprintf(files[file_count++], sizeof(files[0]), "%s", ent->d_name);
  }
  closedir(d);
  qsort(files, (size_t)file_count, sizeof(files[0]), compare_names);
}

static void show_import(void) {
  char body[1024];
  screen = S_IMPORT;
  scan_files();
  snprintf(body, sizeof(body),
           "Copy a .txt file into\n%s\n\nEach line holds an otpauth:// link or a Google "
           "Authenticator export (otpauth-migration://). Decode the QR codes on a PC or "
           "phone first.%s%s",
           import_dir, file_count ? "" : "\n\nNo .txt files found yet.",
           more_files ? "\n\nOnly the first 10 files are listed." : "");
  begin("Import accounts", body);
  for (int i = 0; i < file_count; i++) button(A_FILE + (uint32_t)i, 0, files[i], NULL);
  button(A_BACK, 0, "Back", NULL);
  commit(A_BACK);
}

static int same_entry(const struct otp_entry *a, const struct otp_entry *b) {
  return a->secret_len == b->secret_len && !memcmp(a->secret, b->secret, a->secret_len) &&
         !strcmp(a->issuer, b->issuer) && !strcmp(a->name, b->name);
}

static void show_preview(void) {
  char body[1024], label[96], value[64];
  static const char *const algos[] = {"SHA1", "SHA256", "SHA512"};
  const int room = VAULT_MAX - vault.count;
  int n = snprintf(body, sizeof(body), "%s\n\n%d new account%s found.", chosen_file,
                   pending_count, pending_count == 1 ? "" : "s");
#define MORE(...) \
  if (n < (int)sizeof(body)) n += snprintf(body + n, sizeof(body) - (size_t)n, __VA_ARGS__)
  if (pending_dupes) MORE("\n%d already in the vault.", pending_dupes);
  if (pending_stats.skipped_hotp) MORE("\n%d counter-based (HOTP) skipped: not supported.", pending_stats.skipped_hotp);
  if (pending_stats.skipped_md5) MORE("\n%d MD5 skipped: not supported.", pending_stats.skipped_md5);
  if (pending_stats.invalid) MORE("\n%d line(s) or entries could not be read.", pending_stats.invalid);
  if (pending_count > room) MORE("\nOnly %d fit: the vault holds at most %d.", room, VAULT_MAX);
#undef MORE
  screen = S_PREVIEW;
  begin("Import preview", body);
  for (int i = 0; i < pending_count && i < PREVIEW_ROWS; i++) {
    const struct otp_entry *e = &pending[i];
    entry_label(e, label, sizeof(label));
    snprintf(value, sizeof(value), "%s, %u digits, %u s", algos[e->algo], e->digits, e->period);
    metric(ROW_CODE + (uint32_t)i, 0, label, value);
  }
  const int count = pending_count < room ? pending_count : room;
  snprintf(label, sizeof(label), "Import %d account%s", count, count == 1 ? "" : "s");
  button(A_CONFIRM, count ? PRIMARY : DISABLED, label, NULL);
  button(A_CANCEL, 0, "Cancel", NULL);
  commit(A_CANCEL);
}

static void choose_file(int index) {
  char path[512];
  snprintf(chosen_file, sizeof(chosen_file), "%s", files[index]);
  snprintf(path, sizeof(path), "%s/%s", import_dir, chosen_file);
  const int in = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat st;
  if (in < 0 || fstat(in, &st) || !S_ISREG(st.st_mode) || st.st_size > IMPORT_MAX_BYTES) {
    if (in >= 0) close(in);
    status(in < 0 ? "Could not open %s" : "%s is not a regular file under 1 MiB", chosen_file);
    return;
  }
  size_t len = 0;
  ssize_t r;
  while (len < (size_t)st.st_size &&
         ((r = read(in, file_buf + len, (size_t)st.st_size - len)) > 0 || (r < 0 && errno == EINTR)))
    if (r > 0) len += (size_t)r;
  close(in);
  memset(&pending_stats, 0, sizeof(pending_stats));
  const int found = import_text(file_buf, len, pending, IMPORT_MAX_ENTRIES, &pending_stats);
  crypto_wipe(file_buf, len);
  /* Drop entries already in the vault or repeated across export batches. */
  pending_count = pending_dupes = 0;
  for (int i = 0; i < found; i++) {
    int dupe = 0;
    for (int j = 0; j < vault.count && !dupe; j++) dupe = same_entry(&pending[i], &vault.entries[j]);
    for (int j = 0; j < pending_count && !dupe; j++) dupe = same_entry(&pending[i], &pending[j]);
    if (dupe) pending_dupes++;
    else pending[pending_count++] = pending[i];
  }
  crypto_wipe(pending + pending_count, sizeof(pending[0]) * (size_t)(IMPORT_MAX_ENTRIES - pending_count));
  show_preview();
}

static void show_imported(int count) {
  char body[512];
  screen = S_IMPORTED;
  snprintf(body, sizeof(body),
           "Imported %d account%s.\n\n%s still holds the secrets in plain text. Delete it "
           "now? It is overwritten first, but flash storage may keep old copies.",
           count, count == 1 ? "" : "s", chosen_file);
  begin("Import complete", body);
  button(A_DELETE_FILE, DESTRUCTIVE, "Delete the import file", NULL);
  button(A_KEEP_FILE, 0, "Keep the file", NULL);
  commit(A_KEEP_FILE);
}

static int shred(const char *path) {
  static const char zeros[4096];
  const int out = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat st;
  if (out < 0) return -1;
  if (!fstat(out, &st) && S_ISREG(st.st_mode)) {
    for (off_t done = 0; done < st.st_size;) {
      const size_t chunk = st.st_size - done < (off_t)sizeof(zeros) ? (size_t)(st.st_size - done) : sizeof(zeros);
      const ssize_t w = write(out, zeros, chunk);
      if (w <= 0) break;
      done += w;
    }
    fsync(out);
  }
  close(out);
  return unlink(path);
}

static void show_settings(void) {
  char utc[48], count[16];
  screen = S_SETTINGS;
  begin("Settings",
        "The vault is only as strong as your PIN: anyone who copies vault.bin can try PINs "
        "offline. Recovery runs as root, so other root tools can read memory while the "
        "vault is unlocked. Codes depend on the device time below. The network time check "
        "asks a public time server over UDP and never changes the clock.");
  utc_now(utc, sizeof(utc));
  snprintf(count, sizeof(count), "%d", vault.count);
  metric(ROW_UTC, METRIC_ACCENT, "Device time", utc);
  ntp_metric();
  metric(2, 0, "Accounts", count);
  metric(3, 0, "Vault file", vault_path);
  metric(4, 0, "Auto-lock", "After 5 minutes without input");
  button(A_CHECK_TIME, ntp_state == NTP_WAIT ? DISABLED : 0, "Check network time", NULL);
  button(A_CHANGE_PIN, 0, "Change PIN", NULL);
  button(A_DELETE_LIST, vault.count ? 0 : DISABLED, "Delete an account", NULL);
  button(A_LOCK, 0, "Lock now", NULL);
  button(A_BACK, 0, "Back", NULL);
  commit(A_BACK);
}

static void show_delete_list(void) {
  const int pages = vault.count ? (vault.count + ACCOUNTS_PER_PAGE - 1) / ACCOUNTS_PER_PAGE : 1;
  if (page >= pages) page = pages - 1;
  screen = S_DELETE_LIST;
  begin("Delete an account", "Choose the account to remove from the vault.");
  const int first = page * ACCOUNTS_PER_PAGE;
  for (int i = first; i < vault.count && i < first + ACCOUNTS_PER_PAGE; i++) {
    const struct otp_entry *e = &vault.entries[i];
    button(A_ACCOUNT + (uint32_t)(i - first), DESTRUCTIVE, e->issuer[0] ? e->issuer : e->name,
           e->issuer[0] ? e->name : NULL);
  }
  if (page > 0) button(A_PREV, 0, "Previous page", NULL);
  if (page + 1 < pages) button(A_NEXT, 0, "Next page", NULL);
  button(A_BACK, 0, "Back", NULL);
  commit(A_BACK);
}

static void show_delete_confirm(void) {
  char body[512], label[96];
  entry_label(&vault.entries[delete_index], label, sizeof(label));
  snprintf(body, sizeof(body),
           "%s\n\nThis removes the account from the vault. Make sure you can still sign in "
           "another way.",
           label);
  screen = S_DELETE_CONFIRM;
  begin("Delete this account?", body);
  button(A_CONFIRM, DESTRUCTIVE, "Delete", NULL);
  button(A_CANCEL, 0, "Cancel", NULL);
  commit(A_CANCEL);
}

static int ensure_dirs(void) {
  char path[320];
  struct stat st;
  /* mkdir -p, 0700: the vault and plaintext imports are nobody else's business. */
  for (char *p = strchr(dir + 1, '/');; p = strchr(p + 1, '/')) {
    snprintf(path, sizeof(path), "%.*s", p ? (int)(p - dir) : (int)strlen(dir), dir);
    mkdir(path, 0700);
    if (!p) break;
  }
  mkdir(import_dir, 0700);
  return !stat(dir, &st) && S_ISDIR(st.st_mode) && !stat(import_dir, &st) && S_ISDIR(st.st_mode);
}

static void start(void) {
  if (!(host_features & FEATURE_METRICS)) {
    screen = S_NONE;
    begin("Update AERA Recovery", "This plugin needs a newer AERA Host API 2 with metric rows.");
    commit(0);
    return;
  }
  if (!ensure_dirs()) {
    screen = S_STORAGE;
    char body[512];
    snprintf(body, sizeof(body),
             "%s is not available. Decrypt or mount internal storage (/data), then try again.", dir);
    begin("Storage unavailable", body);
    button(A_RETRY, PRIMARY, "Try again", NULL);
    commit(0);
    return;
  }
  show_pin(access(vault_path, F_OK) ? P_CREATE : P_UNLOCK);
}

/* ---- input ---- */

static void after_unlock(void) {
  unlocked = 1;
  page = 0;
  last_input_ms = now_ms();
  show_codes();
  if (ntp_state == NTP_IDLE) ntp_start();
}

static void pin_ok(void) {
  const size_t len = strlen(pin);
  switch (pin_mode) {
    case P_CREATE:
    case P_CHANGE_NEW:
      if (len < PIN_MIN) {
        status("Use at least %d digits", PIN_MIN);
        return;
      }
      memcpy(first_pin, pin, sizeof(pin));
      show_pin(pin_mode == P_CREATE ? P_CONFIRM : P_CHANGE_CONFIRM);
      return;
    case P_CONFIRM:
      if (strcmp(pin, first_pin)) {
        show_pin(P_CREATE);
        status("The PINs did not match. Start again.");
      } else {
        status("Creating the vault...");
        if (vault_create(&vault, pin) || vault_save(&vault, vault_path)) {
          wipe_all();
          show_pin(P_CREATE);
          status("Could not write %s", vault_path);
        } else {
          after_unlock();
        }
      }
      break;
    case P_UNLOCK: {
      status("Unlocking...");
      const int r = vault_open(&vault, vault_path, pin);
      crypto_wipe(pin, sizeof(pin));
      if (r == VAULT_OK) after_unlock();
      else if (r == VAULT_BAD_PIN) status("Wrong PIN");
      else if (r == VAULT_CORRUPT) status("The vault file is damaged or not an AERA vault");
      else status("Could not read %s", vault_path);
      break;
    }
    case P_CHANGE_OLD:
      status("Checking...");
      if (vault_check_pin(&vault, pin) == VAULT_OK) show_pin(P_CHANGE_NEW);
      else show_pin(P_CHANGE_OLD), status("Wrong PIN");
      break;
    case P_CHANGE_CONFIRM: {
      if (strcmp(pin, first_pin)) {
        show_pin(P_CHANGE_NEW);
        status("The PINs did not match. Start again.");
        break;
      }
      status("Re-encrypting...");
      uint8_t old_key[32], old_salt[16];
      const uint32_t old_kib = vault.kdf_kib, old_passes = vault.kdf_passes;
      memcpy(old_key, vault.key, 32);
      memcpy(old_salt, vault.salt, 16);
      if (vault_rekey(&vault, pin) || vault_save(&vault, vault_path)) {
        memcpy(vault.key, old_key, 32);
        memcpy(vault.salt, old_salt, 16);
        vault.kdf_kib = old_kib, vault.kdf_passes = old_passes;
        show_settings();
        status("Could not save; the old PIN still applies");
      } else {
        show_settings();
        status("PIN changed");
      }
      crypto_wipe(old_key, sizeof(old_key));
      break;
    }
  }
  crypto_wipe(pin, sizeof(pin));
  crypto_wipe(first_pin, sizeof(first_pin));
}

static void pin_input(uint32_t id) {
  static uint64_t last_erase_ms; /* Delete twice within a second clears the PIN */
  const size_t len = strlen(pin);
  const uint64_t now = now_ms();
  const int double_tap = last_erase_ms && now - last_erase_ms < 1000;
  last_erase_ms = id == A_ERASE ? now : 0;
  if (id >= A_DIGIT && id <= A_DIGIT + 9) {
    if (len < PIN_MAX) pin[len] = (char)('0' + (id - A_DIGIT));
    pin_status();
  } else if (id == A_ERASE) {
    if (double_tap) crypto_wipe(pin, sizeof(pin)); /* never cancels: a third quick tap is a no-op */
    else if (len) pin[len - 1] = '\0';
    else if (pin_mode >= P_CHANGE_OLD) {
      crypto_wipe(first_pin, sizeof(first_pin));
      show_settings();
      return;
    }
    pin_status();
  } else if (id == A_OK) {
    pin_ok();
  }
}

static void action(uint32_t id) {
  last_input_ms = now_ms();
  switch (screen) {
    case S_NONE: break;
    case S_STORAGE:
      if (id == A_RETRY) start();
      break;
    case S_PIN: pin_input(id); break;
    case S_CODES:
      if (id == A_PREV && page > 0) page--, show_codes();
      else if (id == A_NEXT) page++, show_codes();
      else if (id == A_IMPORT) show_import();
      else if (id == A_SETTINGS) show_settings();
      else if (id == A_LOCK) wipe_all(), show_pin(P_UNLOCK), status("Locked");
      break;
    case S_IMPORT:
      if (id == A_BACK) show_codes();
      else if (id >= A_FILE && id < A_FILE + (uint32_t)file_count) choose_file((int)(id - A_FILE));
      break;
    case S_PREVIEW:
      if (id == A_CONFIRM) {
        const int before = vault.count, room = VAULT_MAX - before;
        const int count = pending_count < room ? pending_count : room;
        memcpy(vault.entries + before, pending, sizeof(pending[0]) * (size_t)count);
        vault.count += count;
        crypto_wipe(pending, sizeof(pending));
        if (vault_save(&vault, vault_path)) {
          crypto_wipe(vault.entries + before, sizeof(pending[0]) * (size_t)count);
          vault.count = before;
          show_codes();
          status("Could not save the vault; nothing was imported");
        } else {
          show_imported(count);
        }
      } else if (id == A_CANCEL) {
        crypto_wipe(pending, sizeof(pending));
        show_import();
      }
      break;
    case S_IMPORTED:
      if (id == A_DELETE_FILE || id == A_KEEP_FILE) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", import_dir, chosen_file);
        const int failed = id == A_DELETE_FILE && shred(path);
        page = 0;
        show_codes();
        if (id == A_DELETE_FILE) status(failed ? "Could not delete %s" : "Deleted %s", chosen_file);
      }
      break;
    case S_SETTINGS:
      if (id == A_BACK) show_codes();
      else if (id == A_CHECK_TIME && ntp_state != NTP_WAIT) ntp_start(), show_settings();
      else if (id == A_CHANGE_PIN) show_pin(P_CHANGE_OLD);
      else if (id == A_DELETE_LIST && vault.count) page = 0, show_delete_list();
      else if (id == A_LOCK) wipe_all(), show_pin(P_UNLOCK), status("Locked");
      break;
    case S_DELETE_LIST:
      if (id == A_BACK) show_settings();
      else if (id == A_PREV && page > 0) page--, show_delete_list();
      else if (id == A_NEXT) page++, show_delete_list();
      else if (id >= A_ACCOUNT && id < A_ACCOUNT + ACCOUNTS_PER_PAGE &&
               page * ACCOUNTS_PER_PAGE + (int)(id - A_ACCOUNT) < vault.count) {
        delete_index = page * ACCOUNTS_PER_PAGE + (int)(id - A_ACCOUNT);
        show_delete_confirm();
      }
      break;
    case S_DELETE_CONFIRM:
      if (id == A_CANCEL) show_delete_list();
      else if (id == A_CONFIRM) {
        struct otp_entry removed = vault.entries[delete_index];
        const size_t tail = (size_t)(vault.count - delete_index - 1);
        memmove(&vault.entries[delete_index], &vault.entries[delete_index + 1], tail * sizeof(removed));
        crypto_wipe(&vault.entries[--vault.count], sizeof(removed));
        if (vault_save(&vault, vault_path)) {
          memmove(&vault.entries[delete_index + 1], &vault.entries[delete_index], tail * sizeof(removed));
          vault.entries[delete_index] = removed;
          vault.count++;
          show_delete_list();
          status("Could not save the vault; nothing was deleted");
        } else if (vault.count) {
          show_delete_list();
          status("Account deleted");
        } else {
          show_settings();
          status("Account deleted");
        }
        crypto_wipe(&removed, sizeof(removed));
      }
      break;
  }
}

int main(void) {
#ifdef __linux__
  prctl(PR_SET_DUMPABLE, 0); /* no core dumps or ptrace by non-root */
  mlockall(MCL_CURRENT | MCL_FUTURE); /* best effort: keep secrets out of swap */
#endif
  const char *base = getenv("AERA_AUTH_DIR"); /* tests only; AERA's env is fixed */
  snprintf(dir, sizeof(dir), "%s", base && *base == '/' ? base : "/sdcard/AERA/authenticator");
  snprintf(vault_path, sizeof(vault_path), "%s/vault.bin", dir);
  snprintf(import_dir, sizeof(import_dir), "%s/import", dir);
  const char *port = getenv("AERA_NTP_TEST_PORT"); /* tests only: 127.0.0.1:port */
  if (base && port) ntp_test_port = atoi(port);

  sendm(HELLO, 0, AERA_API, AERA_API, NULL, "Rec Authenticator");
  int started = 0;
  for (;;) {
    int timeout = -1;
    if (unlocked) {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      timeout = 1000 - (int)(ts.tv_nsec / 1000000) + 5; /* just past each second */
    }
    if (ntp_fd >= 0) {
      const uint64_t now = now_ms();
      const int left = ntp_deadline > now ? (int)(ntp_deadline - now) : 0;
      if (timeout < 0 || left < timeout) timeout = left;
    }
    struct pollfd p[2] = {{fd, POLLIN, 0}, {ntp_fd, POLLIN, 0}};
    const int r = poll(p, ntp_fd >= 0 ? 2 : 1, timeout);
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) die();
    if (ntp_fd >= 0 && (p[1].revents || now_ms() >= ntp_deadline)) ntp_poll();
    if (!p[0].revents) {
      if (r == 0) tick();
      continue;
    }
    struct message m;
    ssize_t n;
    do n = recv(fd, &m, sizeof(m), MSG_TRUNC);
    while (n < 0 && errno == EINTR);
    if (n != (ssize_t)sizeof(m) || m.magic != AERA_MAGIC || m.version != AERA_API ||
        !memchr(m.title, 0, sizeof(m.title)) || !memchr(m.text, 0, sizeof(m.text)))
      die();
    if (m.kind == HELLO_ACK) {
      host_features = m.flags;
    } else if (m.kind == LIFECYCLE && m.value == RESUME && !started) {
      started = 1;
      start();
    } else if (m.kind == LIFECYCLE && m.value == STOP) {
      die();
    } else if (m.kind == ACTION && started) {
      action(m.request_id);
    }
  }
}
