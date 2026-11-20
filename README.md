# libcomms-sha256-hook

Frida instrumentation for recovering the CIP challenge/response authentication
in `libComms.dll` (the EtherNet/IP comms engine used by the controller
emulator). The device answers a 128-byte server challenge with a 20-byte proof
computed by a **SHA-256-based keyed KDF**; this hook captures the exact bytes
fed to SHA-256 and the auth key, so the construction can be reproduced.

Target: **32-bit** `libComms.dll`, Ghidra image base `0xDA000000`.

## What it hooks

Addresses are `module base + RVA` (RVA = Ghidra address − `0xDA000000`):

| RVA | Function | What the hook logs |
|------|----------|--------------------|
| `0x87c0` | `SHA256_Update(ctx, data, len)` | every chunk fed into SHA-256 |
| `0x8b20` | `SHA256_Final` | a `--- FINAL ---` marker per hash-block boundary |
| `0x42650` | `cip_auth_validate_challenge` | the key pointer/length (`ctx+0x1c` / `ctx+0x88`) and the key bytes |

The `UPDATE` dumps between two `FINAL` markers are the exact preimage of one
SHA-256 call. The `cip_auth_validate_challenge` block prints the auth key
directly.

---

## Instructions (portable, no Python)

Uses the standalone **`frida-inject`** executable — no `pip`, no install.

### 1. Get `frida-inject` (standalone binary)

1. Open the Frida releases page: <https://github.com/frida/frida/releases> (latest).
2. Download **`frida-inject-<version>-windows-x86.exe.xz`** — the **x86 (32-bit)**
   build. It must match the 32-bit emulator process, *not* `x86_64`.
3. It is `.xz`-compressed. Decompress with **7-Zip** (portable `7zr.exe` works)
   → `frida-inject-<version>-windows-x86.exe`. Rename it to **`frida-inject.exe`**.
4. Put `frida-inject.exe` and `hook.js` (from this repo) in the same folder.

### 2. Find the emulator's process

Task Manager → **Details** tab → find the emulator executable that the parent
app launched. Note its exact name (e.g. `EmulatorXYZ.exe`) or its PID.

### 3. Attach and start capturing

Open a terminal in that folder (run it **as Administrator** if the emulator is
elevated or runs as a service), then:

```
frida-inject.exe -n EmulatorXYZ.exe -s hook.js > capture.txt 2>&1
```

or by PID:

```
frida-inject.exe -p 1234 -s hook.js > capture.txt 2>&1
```

`capture.txt` should begin with `[+] libComms.dll base=0x...`. If it instead
says "not found" and lists `/comm/i` modules, copy the real module name into
`MODNAME` at the top of `hook.js` and re-run. Leave it attached.

### 4. Trigger one handshake

With `frida-inject` still attached, run the client (e.g. the pycomm2 tool) so it
connects and authenticates **once**. That drives the device-side auth and fills
the log.

### 5. Stop and collect

Let it run through at least one `==== cip_auth_validate_challenge ====` block
(with the `UPDATE`/`FINAL` lines around it), then **Ctrl-C** to detach.
`capture.txt` is saved.

---

## What you get

- The `cip_auth_validate_challenge` block prints `key_ptr`, `key_len`, and the
  **key bytes**. Run two separate handshakes to compare: identical key across
  sessions → long-term pre-shared secret; different each time → derived session
  key.
- The `UPDATE` → `FINAL` groups give the exact byte string fed to SHA-256, which
  confirms whether it is stock SHA-256 and pins down the
  `f(key, challenge) → 20 bytes` construction.

## Notes / gotchas

- **Architecture must match**: 32-bit `frida-inject` for the 32-bit emulator, or
  injection fails.
- EDR/antivirus may flag Frida injection — allow it, and do this on a lab /
  standby instance, not live-control gear.
- The log is noisy (it hooks every SHA-256 update in the process); the `====`
  markers bracket the part that matters.
- `capture.txt` contains the real auth key — treat it as sensitive; don't post
  it publicly.

## Pure-GUI fallback (no command line)

**x32dbg** portable (<https://x64dbg.com>, use the 32-bit `x32dbg.exe` from the
zip): File → Attach to the emulator process, set a breakpoint at
`<libComms base>+0x87c0`, and on each hit read `[esp+8]` (data pointer) and
`[esp+0xc]` (length) and dump. Works, but it is manual one hit at a time;
`frida-inject` auto-logs everything, so prefer that.
