#!/usr/bin/env bash
# Compila el firmware y genera un .bin único (offset 0x0) para instalar desde el navegador.
# Uso: FQBN=esp32:esp32:esp32 ./build.sh [carpeta_salida]
set -euo pipefail
cd "$(dirname "$0")"
FQBN="${FQBN:-esp32:esp32:esp32}"
OUT="${1:-build}"
mkdir -p "$OUT"
arduino-cli compile \
  --fqbn "${FQBN}:PartitionScheme=huge_app" \
  --output-dir "$OUT" \
  --warnings default \
  pc-unlock
BOOT_APP0="$(find "${ESP32_CORE_DIR:-$HOME/.arduino15/packages/esp32/hardware/esp32}" -name boot_app0.bin | head -1)"
python3 -m esptool --chip esp32 merge-bin -o "$OUT/pc-unlock-merged.bin" \
  --flash-mode dio --flash-freq 80m --flash-size 4MB \
  0x1000 "$OUT/pc-unlock.ino.bootloader.bin" \
  0x8000 "$OUT/pc-unlock.ino.partitions.bin" \
  0xe000 "$BOOT_APP0" \
  0x10000 "$OUT/pc-unlock.ino.bin"
ls -la "$OUT"/*.bin
