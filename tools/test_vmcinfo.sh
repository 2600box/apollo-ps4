#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <vmc_path> <slot> <rawkey_hex> [out_mcd]" >&2
  exit 1
fi

VMC_PATH=$1
SLOT=$2
RAWKEY_HEX=$3
OUT_MCD=${4:-"slot_${SLOT}.mcd"}

./tools/vmcinfo --verbose --slot "$SLOT" --rawkey-hex "$RAWKEY_HEX" --decrypt "$OUT_MCD" "$VMC_PATH"

if [[ ! -f "$OUT_MCD" ]]; then
  echo "FAIL: decrypted output not created: $OUT_MCD" >&2
  exit 1
fi

SIZE=$(wc -c < "$OUT_MCD" | tr -d ' ')
if [[ "$SIZE" != "131072" ]]; then
  echo "FAIL: unexpected MCD size $SIZE (expected 131072)" >&2
  exit 1
fi

MAGIC=$(xxd -p -l 2 "$OUT_MCD")
if [[ "$MAGIC" != "4d43" ]]; then
  echo "FAIL: missing MC header at offset 0 (got $MAGIC)" >&2
  exit 1
fi

if ! ./tools/vmcinfo --slot "$SLOT" "$OUT_MCD" | rg -q "Signature: present"; then
  echo "FAIL: vmcinfo did not report a valid PS1 signature" >&2
  exit 1
fi

echo "PASS: $OUT_MCD looks like a valid PS1 .mcd"
