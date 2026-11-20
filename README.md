# libcomms-sha256-hook

Frida instrumentation script for analyzing the CIP challenge/response
authentication in `libComms.dll` (32-bit, Ghidra image base `0xDA000000`).

It hooks, by `module base + RVA`:

- `0x87c0` `SHA256_Update(ctx, data, len)` — logs every chunk fed into SHA-256
- `0x8b20` `SHA256_Final` — marks each hash-block boundary
- `0x42650` `cip_auth_validate_challenge` — logs the key pointer/length
  (`ctx+0x1c` / `ctx+0x88`) and the key bytes

## Usage (no Python; standalone `frida-inject`)

Download `frida-inject-<ver>-windows-x86.exe` from the Frida GitHub releases
(32-bit, to match the 32-bit target), then:

```
frida-inject.exe -n <emulator.exe> -s hook.js > capture.txt 2>&1
```

Trigger one handshake, then inspect `capture.txt`. The `UPDATE` dumps between
two `FINAL` markers are the exact preimage of one SHA-256 call; the
`cip_auth_validate_challenge` block prints the auth key.

If the module name differs from `libComms.dll`, edit `MODNAME` at the top of
`hook.js`.
