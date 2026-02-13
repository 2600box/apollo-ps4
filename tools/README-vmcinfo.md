# vmcinfo (host utility)

`vmcinfo` is a standalone terminal utility for amd64 Linux/macOS that inspects PlayStation `.vmc` files.

Build:

```bash
make vmcinfo
```

Run:

```bash
./tools/vmcinfo /path/to/card.vmc
```

You can pass multiple files at once.

## Decrypting PS1HD embedded slots

Apollo on PS4 does **not** decrypt PS1HD payloads in userspace C code; it mounts save-data via `sceFsMountSaveData` with the decrypted sealed key and receives plaintext through the kernel PFS path. For host-side decryption with a known raw key, `vmcinfo` now uses a deterministic PS1HD AES-XTS path that matches the PS1HD container layout: 32-byte raw key as XTS key material (AES-128-XTS), 512-byte data unit, little-endian 64-bit tweak, and sector base `(0x8000 + slot_index * 0x20000) / 512`. No heuristic key/tweak probing is used when `--rawkey`/`--rawkey-hex` is provided.

Use a raw key file:

```bash
./tools/vmcinfo --slot 0 --rawkey /path/to/rawkey.bin --decrypt out.mcd /path/to/card.vmc
```

Or inline hex:

```bash
./tools/vmcinfo --slot 0 --rawkey-hex "65be 19ad 61dd 834f ca4f 5fad cd4e 26fa bf94 4f13 e213 8a8a 0faf 1199 2229 e3cb" --decrypt out.mcd /path/to/card.vmc
```

Dump a specific embedded slot (writes valid `.mcd` when possible, else `.raw`/`.cand`):

```bash
./tools/vmcinfo --dump-slot 2 slot2_out.mcd --rawkey-hex "65be19ad61dd834fca4f5fadcd4e26fabf944f13e2138a8a0faf11992229e3cb" /path/to/PS1.VMC
```

Verbose decrypt diagnostics (algorithm path, data-unit size, tweak mode, key fingerprint, and validation-failure reason):

```bash
./tools/vmcinfo --verbose --slot 2 --decrypt slot2_out.mcd --rawkey-hex "65be19ad61dd834fca4f5fadcd4e26fabf944f13e2138a8a0faf11992229e3cb" /path/to/PS1.VMC
```

## Quick self-test

A valid raw PS1 memory card is exactly 131072 bytes and starts with `MC`:

```bash
stat -c '%s' slot2_out.mcd
hexdump -C -n 32 slot2_out.mcd
```

Expected first bytes include `4d 43` (`MC`).


## Repro check script

Use `tools/test_vmcinfo.sh` to run a host-side decrypt/validation check:

```bash
make vmcinfo
./tools/test_vmcinfo.sh /path/to/PS1.VMC 2 "65be19ad61dd834fca4f5fadcd4e26fabf944f13e2138a8a0faf11992229e3cb" slot2.mcd
```

The script verifies output size, `MC` at offset 0, and re-runs `vmcinfo` to confirm the slot parses as a PS1 card signature.
