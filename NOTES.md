# Rec Authenticator: developer notes

How the plugin fits the AERA host, why it looks the way it does, and how to
test it. User-facing documentation is in `README.md`.

## AERA host findings (recovery source as of 2026-10-14, commit 2800f16)

Sources:
- `AERA-Recovery/android_bootable_recovery` at `aeraui/features/plugin_api/`
  (`README.md`, `protocol.hpp`, `session.cpp`, `launcher.cpp`) and
  `aeraui/scenes/generic_plugin_scene.cpp`.
- `AERA-Plugins/settings-backup` (the Host API 2 reference, `source/main.c`)
- `AERA-Plugins/sysinfo` (`build.sh`, metric refresh loop)
- `AERA-Plugins/registry` (`README.md`, `scripts/package_aerap.py`)

### 1. Protocol
- fd 4 is an `AF_UNIX SOCK_SEQPACKET` socket. One packet is one message, and
  every packet is exactly 1144 bytes:
  `u32 magic=0x41325049 ("A2PI"), u32 version=2, u32 kind, u32 request_id,
  u32 value, u32 flags, char title[96], char text[1024]`. Both strings must be
  NUL-terminated. If any packet is invalid, the host closes the session.
- Handshake: the worker sends `HELLO` with `value` set to its minimum version
  and `flags` set to its maximum. The host replies with `HELLO_ACK` (`flags`
  carries the feature bits: 1 = metrics, 2 = back navigation) and then
  `LIFECYCLE/RESUME`. The worker has 5 seconds to send `HELLO`.
- Messages from the worker: `HELLO`=1, `BEGIN_PAGE`=2, `ADD_BUTTON`=3,
  `COMMIT_PAGE`=4, `SET_STATUS`=5, `REQUEST_OPERATION`=6, `CLOSE`=7,
  `ADD_SECTION`=8, `ADD_METRIC`=9, `UPDATE_METRIC`=10, `SET_BACK_ACTION`=11.
- Messages from the host: `HELLO_ACK`=64, `ACTION`=65 (`request_id` is the
  button ID), `LIFECYCLE`=66 (1 = resume, 2 = pause, 3 = stop),
  `OPERATION_RESULT`=67.
- Widgets: a page has a title and a body text, up to 16 section headers, up to
  64 metric rows (a label and a value, with a good, warning, critical or accent
  tint) and up to 12 buttons (title, detail line, and the flags primary,
  destructive and disabled). There is also one status line at the bottom.
  Buttons render as full-width cards stacked vertically, and the page scrolls.
  **Metric rows cannot be tapped.** Only buttons produce actions.
- Duplicate IDs, more than the limits, or bad flags kill the session.

### 2. Text input
**There is no text input and no keyboard.** Each entry is therefore a numeric
**PIN** typed on a 12-button pad (`0`–`9`, `Delete`, `OK`). Because 12 buttons
is the page maximum, the PIN pad has no Cancel button. The back gesture leaves
the plugin instead. A PIN has low entropy, so the plugin requires at least
8 digits (see the security notes below).

### 3. Filesystem and permissions
- The worker runs as **root (UID/GID 0) with no sandbox**: no chroot, seccomp,
  namespaces or rlimits. It has the same filesystem access as recovery.
  There is no storage permission and no per-plugin data directory.
- `cwd` is the extracted runtime under `/tmp/aera-p2-XXXXXX`, which lives in
  RAM and disappears after the session. `HOME` and `TMPDIR` are `/tmp`.
- Every permission the host recognizes: `display`, `touch-input`,
  `settings-backup`, `settings-restore`, `android-settings-backup`,
  `android-settings-restore`, `screen-mirror`. Any other name makes the
  manifest invalid. The plugin requests only `display` and `touch-input`.
- Vault: `/sdcard/AERA/authenticator/vault.bin`. Import files go in
  `/sdcard/AERA/authenticator/import/`. `/sdcard` exists only when `/data` is
  decrypted and mounted.
- **The executable path is hard-coded by the launcher** as `usr/bin/aera-plugin`.

### 4. Toolchain
The official plugins build with AOSP prebuilt clang r530567 using
`--target=aarch64-unknown-linux-musl`, the AOSP musl sysroot, `-static -Os`,
`lld`, and `--gc-sections -s`. Static binaries are executed directly. This
project uses `zig cc -target aarch64-linux-musl -static`, which is the same
libc (musl), the same static link and the same target without an AOSP tree.

### 5. Timers
The worker can send messages whenever it wants. `UPDATE_METRIC` changes a row's
value in place without re-rendering the page. sysinfo uses
`poll(fd, 1000 ms)` and pushes updates. The cap is 128 worker messages per
second, so one update per visible code per second is fine with up to 64 rows.

### 6. Time
- `CLOCK_REALTIME` works, but a recovery boot may have the wrong time if the
  ROM's time daemon has not set the RTC offset. The UTC time is always shown.
- There is no network permission, but the worker shares recovery's network
  namespace, so it reaches NTP over UDP directly. Recovery has no
  `/etc/resolv.conf`, so DNS does not work from a static musl binary; the
  check uses IP literals instead (see "Network time check").

### 7. Limits
- Host API 2 sets no memory or CPU limits. Argon2id with 64 MiB and 3 passes
  is fine.
- Payload: at most 512 MiB compressed or expanded, and at most 4096 files.
  Manifest: at most 64 KiB and at most 16 permissions.
- Wire: 128 messages per second, 12 buttons, 64 metrics, 16 sections,
  96-byte titles and 1024-byte text.

### Lifecycle
The host sends `RESUME` after the handshake. When the user leaves the scene,
the host sends `STOP` and `CLOSE`, then kills the process group (SIGTERM, then
SIGKILL after 500 ms). The current host never sends `PAUSE`. Backgrounding the
plugin therefore kills the process and wipes keys in memory, which is the
lock-on-background behavior. An idle timer covers the rest.

## Build and test
- `make test`: builds the RFC, importer and vault unit tests (`tests/test.c`)
  with ASan and UBSan, then runs `tests/e2e.py`. The e2e test acts as a fake
  AERA host: it drives the real plugin over fd 4, enforces the host's protocol
  rules (packet size, button and metric limits, back action, 128 messages per
  second) and covers create PIN, import, preview, deleting the import file,
  checking codes against Python's `hmac`, wrong PIN, change PIN, deleting an
  account, and reopening after a restart. On macOS it uses a `SOCK_DGRAM`
  socketpair because Darwin has no `AF_UNIX SOCK_SEQPACKET`.
- `make fuzz FUZZ_TIME=300`: runs libFuzzer on both importers. On macOS it
  uses Homebrew LLVM. The first run on 2026-10-15 made 6.3M executions in
  5 minutes with no crashes.
- `make aerap`: cross-compiles with `zig cc` (zig 0.17.0, static
  aarch64-linux-musl), runs `tools/pack.py` (copied from settings-backup),
  updates `plugin.json` and writes `build/Rec-Authenticator-<ver>.aerap` with
  the registry's `package_aerap.py`. The package is about 55 KB.

## Known cosmetic issue
Each PIN digit only sends `SET_STATUS` (one message), so the page does not
re-render. The host still moves its progress bar to 72% on every tap and moves
it to 100% only when a page is committed, so the bar can stay at 72% on the
PIN pad. A full re-render per digit would send 14 messages per tap, which gets
close to the rate limit when someone types fast.

## Design decisions
- The executable is `usr/bin/aera-plugin` because the launcher requires it.
- The plugin uses a PIN because no text input exists.
  The PIN must be at least 8 digits.
- Rows cannot be tapped, so there is no tap to reveal the next code. Instead,
  during the last 10 seconds of a period, the row also shows the next code.
- There is no file picker. Import lists the `*.txt` files in
  `/sdcard/AERA/authenticator/import/` as buttons (10 per page).
- Accounts are deleted from a paged list of buttons.
- Clear on the PIN pad is "tap Delete twice within a second", because the pad
  already uses all 12 buttons. A third quick tap does nothing, so clearing
  never cancels a PIN change by accident.
- Each account on the codes screen is two lines: a section header with
  "Issuer: account", then a metric row whose value is the code and countdown
  (the row title is a single space; the host requires a non-empty title).
  The host allows 16 section headers per page, so the codes screen shows 15
  accounts per page.
- HOTP (counter-based) and MD5 accounts are skipped on import.

## Host limits (need an AERA change)
- **Home tile icon:** the manifest `icon` field is parsed
  (`plugin_manager.cpp`) but never drawn. The launcher picks the icon in
  `GenericPluginIcon` (`launcher_scene.cpp`) and `Icon` (`plugin_scene.cpp`)
  from the plugin id, entry and category; every other generic plugin gets the
  gear (`LV_SYMBOL_SETTINGS`). The manifest says `"icon": "key"` in case a
  later host honours it.
- **PIN grid:** `ActionCard` in `generic_plugin_scene.cpp` always lays
  buttons out as full-width stacked cards, and `ADD_BUTTON` accepts only the
  primary, destructive and disabled flags. A keypad grid needs a new host
  layout flag or widget.
- **Button colours:** buttons come only in default, primary (theme accent)
  and destructive (red). Delete on the PIN pad uses destructive.
- **Custom layouts:** the browser, Telegram, Streams and a few other official
  plugins get native screens drawn by recovery itself, chosen by a hard-coded
  id/type/entry list in `plugin_manager.cpp`. Generic plugins cannot opt in.

## Network time check
- The check only reports the offset. It never sets the clock and never
  adjusts the codes.
- After the first unlock (and on "Check network time" in Settings), the
  plugin sends one SNTP request over UDP to `216.239.35.0`
  (time.google.com), then `162.159.200.1` (time.cloudflare.com), then
  `216.239.35.4`. Each server gets 2 seconds; an ICMP error moves on at once.
  These are anycast addresses; update `ntp_servers` in `src/main.c` if they
  ever change.
- The request carries a random 8-byte nonce in the transmit field instead of
  the device time. A reply counts only if it echoes the nonce, is in server
  mode, has stratum 1-15 and is not unsynchronized. Other packets are ignored
  until the wait runs out.
- The "Network time" row on the codes and settings screens shows
  "Matches", "4.2 s behind", "12 min ahead", "No reply" or "No network"
  (no route to any server). It is green within 3 seconds, yellow up to
  15 seconds and red beyond, where codes will usually be rejected.
- The host sizes a metric row once, when the page renders, and does not
  re-measure it on `UPDATE_METRIC`. A value that grows to two lines later is
  clipped (seen on the device with the first "No reply" text). Every value
  that updates in place (clock, network time, codes) is kept to one line.
- SNTP is not authenticated. An on-path attacker can fake the result, but the
  result is display-only, so the worst case is a misleading row.
- Tests: `test_ntp` in `tests/test.c` checks the offset maths (including the
  2036 era rollover) and rejection rules. `tests/e2e.py` runs a fake SNTP
  server (`AERA_NTP_TEST_PORT`) for the behind, matching and no-reply cases.

## Security notes shown to the user
- The vault is only as strong as the PIN. Someone who copies `vault.bin` can
  brute-force it offline. Argon2id at 64 MiB makes each guess cost about a
  second on a phone, but an 8-digit PIN still has only 10^8 combinations.
  Use 10 or more digits.
- Recovery is a root environment. Any other root plugin or adb shell can read
  process memory while the vault is unlocked.

## Manual device test checklist
- [ ] Install `build/Rec-Authenticator-<ver>.aerap` from Files. The unofficial
      warning appears, and the plugin lands under Unofficial Apps.
- [ ] First run: create a PIN. A PIN shorter than 8 digits is rejected.
      The confirmation must match.
- [ ] Put `export.txt` (GA migration lines or `otpauth://` lines) in
      `/sdcard/AERA/authenticator/import/`, import it, check the preview
      count, and confirm.
- [ ] Delete the import file when offered. Confirm it is gone.
- [ ] Codes match Aegis or Google Authenticator on a phone for at least
      3 accounts (SHA1/6, plus SHA256 or 8 digits if available).
- [ ] The countdown ticks every second, and the next code appears in the last
      10 seconds.
- [ ] Wrong PIN shows an error and stays locked. The vault is unchanged.
- [ ] Leaving the plugin and reopening it asks for the PIN.
- [ ] No input for 5 minutes locks the vault.
- [ ] Reboot to recovery: the vault still unlocks.
- [ ] With a network connection, "Network time" shows "Matches". Without one
      it shows "No network" or "No reply" within a few seconds.
- [ ] Tapping Delete twice quickly clears the PIN.
- [ ] Change PIN, then unlock with the new PIN.
- [ ] Delete one account. It is gone after the vault is locked and unlocked.
