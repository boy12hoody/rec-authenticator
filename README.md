# Rec Authenticator

An unofficial [AERA Recovery](https://github.com/AERA-Recovery) plugin that
shows Google Authenticator–compatible two-factor codes (TOTP) while the phone is
in recovery. Accounts are kept in an encrypted vault unlocked with a PIN.

It is not affiliated with AERA, Google or any account provider.

## Features

- 6–8 digit TOTP codes (SHA-1, SHA-256, SHA-512, 10–300 s periods), refreshed
  every second with a countdown. In the last 10 seconds of a period the next
  code is shown too.
- Import from Google Authenticator export links (`otpauth-migration://`) and
  standard `otpauth://totp/` links.
- Vault encrypted with XChaCha20-Poly1305. The key comes from your PIN through
  Argon2id (64 MiB, 3 passes).
- Locks after 5 minutes without input and whenever you leave the plugin.
- Optional clock check against a public time server. Wrong device time is the
  usual reason codes get rejected.
- Change PIN, delete accounts, securely delete the import file.

Not supported: HOTP (counter-based) and MD5 accounts. They are skipped on
import with a warning.

## Install

1. Download `Rec-Authenticator-<version>.aerap` from the
   [releases page](https://github.com/boy12hoody/rec-authenticator/releases), or build
   it (see below).
2. Copy it to the phone, for example into `Download/`.
3. Boot into AERA Recovery and unlock internal storage (your Android screen
   lock).
4. Open **Files**, choose the `.aerap` file and accept the unofficial-plugin
   warning. The plugin appears on the home screen.

Requirements: AERA Recovery with Host API 2 and an ARM64 (aarch64) device.
Internal storage must be decrypted, because the vault lives there.

## Use

**First run:** choose a PIN of at least 8 digits (10 or more is better), then
enter it again. Tap **Delete** once to remove a digit or twice quickly to clear
the PIN.

**Import accounts:**

1. In Google Authenticator, use *Transfer accounts → Export accounts*. It shows
   one or more QR codes.
2. Read each QR code as text with an **offline** QR scanner. The text starts
   with `otpauth-migration://offline?data=`. `otpauth://totp/...` links from
   other apps work too.
3. Put the links in a `.txt` file, one per line, at
   `/sdcard/AERA/authenticator/import/` (for example with
   `adb push export.txt /sdcard/AERA/authenticator/import/`).
4. In the plugin, choose **Import accounts**, pick the file, check the preview
   and confirm.
5. When asked, choose **Delete the import file**. It holds your secrets in
   plain text.

**Codes screen:** each account shows its name, then the code and seconds left.
The **Device time** and **Network time** rows tell you whether the clock is
right. If network time is red, fix the device clock first.

**Settings:** change PIN, delete an account, check network time again, lock.

## Safety

Read this before you rely on it.

- **The vault is only as strong as your PIN.** Anyone who copies `vault.bin`
  can try PINs offline. Argon2id makes each guess slow (about a second on a
  phone), but 8 digits is only 100 million combinations. Use 10 or more digits.
- **The vault file is on internal storage**
  (`/sdcard/AERA/authenticator/vault.bin`). The folder is root-only, so normal
  Android apps cannot read it, but root apps, anyone with root access, and
  anything else running in recovery can copy it. Only the PIN protects it then.
- **Recovery is a root environment.** Anything else running as root in
  recovery (other plugins, an adb shell) can read the plugin's memory while the
  vault is unlocked. Lock it when you are done.
- **Import files are plain text.** Delete them right after importing, and never
  scan the export QR codes with an online scanner. Flash storage can keep old
  copies even after secure deletion.
- **There is no PIN recovery.** If you forget the PIN, the vault is lost. Keep
  your accounts in another authenticator or keep backup codes.
- **Network time check:** sends one small UDP request to time.google.com
  (216.239.35.0, 216.239.35.4) or time.cloudflare.com (162.159.200.1). It does
  not send your device time or any account data, and it never changes the
  clock. The reply is unauthenticated, so treat the result as a hint.

What the plugin does not do: it asks only for the `display` and `touch-input`
permissions, never writes secrets unencrypted to disk or logs, and wipes keys
from memory on lock and exit.

## Files

| Path | Contents |
|---|---|
| `/sdcard/AERA/authenticator/vault.bin` | Encrypted vault |
| `/sdcard/AERA/authenticator/import/` | Drop import `.txt` files here (files up to 1 MiB, 500 accounts) |

## Build

Needs `make`, a C compiler, Python 3, and [zig](https://ziglang.org) for the
ARM64 cross-compile.

```sh
make test    # unit tests (RFC 4226/6238 vectors, importers, vault) and an
             # end-to-end run against a fake AERA host, with ASan/UBSan
make fuzz    # libFuzzer on both importers (needs clang with libFuzzer)
make aerap   # build/Rec-Authenticator-<version>.aerap
```

To release: bump `version` in `plugin.json`, run `make aerap` (it points
`payload_url` at `releases/download/v<version>/runtime.xz`), then create a
GitHub release `v<version>` with `build/runtime.xz` and the `.aerap`.

Developer notes (host protocol findings, design decisions, test checklist) are
in [NOTES.md](NOTES.md).

## License

Apache-2.0, see [LICENSE](LICENSE).

Includes [Monocypher](https://monocypher.org) 4.0.2 (BSD-2-Clause or CC0, see
`third_party/monocypher/LICENCE.md`). `tools/pack.py` and
`tools/package_aerap.py` come from the AERA Plugins `settings-backup` and
`registry` repositories (Apache-2.0).
