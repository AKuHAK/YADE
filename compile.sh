#!/bin/bash
set -e
cd "$(dirname "$0")"

mkdir -p build release

# ============================================================
# Build shared components ONCE
# ============================================================

echo "=== Building code.bin ==="
mipsel-none-elf-gcc \
    -DBOOT_FILE_SIZE=$(wc -c < fs/BOOT.ELF) \
    -T src/ld/code.ld \
    -march=r5900 \
    -mabi=eabi \
    -mno-gpopt \
    -G0 \
    -nostartfiles \
    -nostdlib \
    -ffreestanding \
    -fno-toplevel-reorder \
    -Os \
    -Wl,-z,max-page-size=0x1 \
    -o build/code.elf \
    src/code/*.S \
    src/code/*.c

mipsel-none-elf-objcopy \
    -O binary \
    -j .text \
    -j .rodata \
    -j .data \
    -j .bss \
    build/code.elf \
    build/code.bin

echo "code.bin size: $(wc -c < build/code.bin)"

echo "=== Building jump.bin (universal, runtime autodetect) ==="
mipsel-none-elf-gcc \
    -T src/ld/jump.ld \
    -march=r5900 \
    -mabi=eabi \
    -mno-gpopt \
    -G0 \
    -nostartfiles \
    -nostdlib \
    -ffreestanding \
    -fno-toplevel-reorder \
    -Os \
    -Wl,-z,max-page-size=0x1 \
    -o build/jump.elf \
    src/jump/crt0.S \
    src/jump/jump.c

mipsel-none-elf-objcopy \
    -O binary \
    -j .text \
    -j .rodata \
    -j .data \
    -j .bss \
    build/jump.elf \
    build/jump.bin

echo "jump.bin size: $(wc -c < build/jump.bin)"

echo "=== Building injector ==="
gcc src/injector/*.c -o build/injector.elf

# Pad code.bin to 8192 bytes once (idempotent after first call)
truncate -s 8192 build/code.bin

# ============================================================
# Create one ISO per DVD player version
# ============================================================

for version in "3.00E" "3.00U" "3.00J" \
               "3.02E" "3.02C" "3.02D" "3.02G" "3.02J" "3.02K" "3.02U" \
               "3.03E" "3.03J" \
               "3.04M" "3.04J"; do

    echo "=== Creating ISO for $version ==="

    # Prepare a fresh build/fs from the source template
    rm -rf build/fs
    cp -r fs build/fs

    # Create template IFO/BUP stubs for all VTS titles
    cp build/fs/VIDEO_TS/VTS_01_0.BUP build/fs/VIDEO_TS/VTS_01_0.IFO
    cp build/fs/VIDEO_TS/VTS_01_0.BUP build/fs/VIDEO_TS/VTS_02_0.BUP
    cp build/fs/VIDEO_TS/VTS_01_0.BUP build/fs/VIDEO_TS/VTS_02_0.IFO
    cp build/fs/VIDEO_TS/VTS_01_0.BUP build/fs/VIDEO_TS/VTS_03_0.BUP
    cp build/fs/VIDEO_TS/VTS_01_0.BUP build/fs/VIDEO_TS/VTS_03_0.IFO
    cp build/fs/VIDEO_TS/VTS_01_0.BUP build/fs/VIDEO_TS/VTS_04_0.BUP
    cp build/fs/VIDEO_TS/VTS_01_0.BUP build/fs/VIDEO_TS/VTS_04_0.IFO

    # Patch IFO/VOB files for this specific version
    ./build/injector.elf "$version"

    # Install the code payload and duplicate VOBs required by DVD-Video spec
    cp build/code.bin build/fs/VIDEO_TS/VIDEO_TS.BUP
    cp build/fs/VIDEO_TS/VTS_01_1.VOB build/fs/VIDEO_TS/VTS_02_1.VOB
    cp build/fs/VIDEO_TS/VTS_01_1.VOB build/fs/VIDEO_TS/VTS_03_1.VOB
    cp build/fs/VIDEO_TS/VTS_01_1.VOB build/fs/VIDEO_TS/VTS_04_1.VOB
    cp build/fs/VIDEO_TS/VTS_04_0.IFO build/fs/VIDEO_TS/VTS_04_0.BUP

    genisoimage -dvd-video -V "" -o "release/exploit_${version}.iso" build/fs/

    echo "Created release/exploit_${version}.iso"
done

echo "=== All ISOs created successfully ==="
