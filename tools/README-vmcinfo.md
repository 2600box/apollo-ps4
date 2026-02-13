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

Apollo on PS4 does **not** decrypt PS1HD payloads in userspace C code; it mounts save-data via `sceFsMountSaveData` with the decrypted sealed key and receives plaintext through the kernel PFS path. The host utility mirrors that post-rawkey payload transform by probing the AES-XTS parameters used by PS1HD payload sectors (key layout, tweak endianness, data-unit size, and sector base), then validates candidates as PS1 `.mcd`.

Use a raw key file:

```bash
./tools/vmcinfo --slot 0 --rawkey /path/to/rawkey.bin --decrypt out.mcd /path/to/card.vmc
```

Or inline hex:

```bash
./tools/vmcinfo --slot 0 --rawkey-hex "be65 ad19 dd61 4f83 4fca ad5f 4ecd fa26 94bf 134f 13e2 8a8a af0f 9911 2922 cbe3" --decrypt out.mcd /path/to/card.vmc
```

Dump a specific embedded slot (writes valid `.mcd` when possible, else `.raw`/`.cand`):

```bash
./tools/vmcinfo --dump-slot 2 slot2_out.mcd --rawkey-hex "be65ad19dd614f834fcaad5f4ecdfa2694bf134f13e28a8aaf0f99112922cbe3" /path/to/PS1.VMC
```

Verbose decrypt diagnostics (algorithm path, data-unit size, tweak mode, key fingerprint, and validation-failure reason):

```bash
./tools/vmcinfo --verbose --slot 2 --decrypt slot2_out.mcd --rawkey-hex "be65ad19dd614f834fcaad5f4ecdfa2694bf134f13e28a8aaf0f99112922cbe3" /path/to/PS1.VMC
```

## Quick self-test

A valid raw PS1 memory card is exactly 131072 bytes and starts with `MC`:

```bash
stat -c '%s' slot2_out.mcd
hexdump -C -n 32 slot2_out.mcd
```

Expected first bytes include `4d 43` (`MC`).
