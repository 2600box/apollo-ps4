# vmcinfo (host utility)

`vmcinfo` is a standalone terminal utility for amd64 Linux (Debian) that inspects PlayStation `.vmc` files.

Build:

```bash
make vmcinfo
```

Run:

```bash
./tools/vmcinfo /path/to/card.vmc
```

You can pass multiple files at once.

Decrypt a PS1 embedded slot using a raw key from hardware/sealedkey processing:

```bash
./tools/vmcinfo --slot 0 --rawkey /path/to/rawkey.bin --decrypt out.mcd /path/to/card.vmc
```

Or pass the key as inline hex (supports `hexdump`-style spacing/newlines and `0x` prefixes):

```bash
./tools/vmcinfo --slot 0 --rawkey-hex "be65 ad19 dd61 4f83 4fca ad5f 4ecd fa26 94bf 134f 13e2 8a8a af0f 9911 2922 cbe3" --decrypt out.mcd /path/to/card.vmc
```
