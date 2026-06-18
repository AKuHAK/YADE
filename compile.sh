#!/bin/bash
cd "$(dirname "$0")"

target_ver=$1
if [[ -z "$target_ver" ]]; then
    target_ver="3.00"
fi
echo "Building universal disc for major version: $target_ver"

rm -rf build
mkdir build
cp --recursive fs build/

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

mipsel-none-elf-objcopy -O binary -j .text -j .rodata -j .data -j .bss build/code.elf build/code.bin
echo "actual code.bin size: $(wc -c < build/code.bin)"

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
    src/jump/*.S \
    src/jump/*.c

mipsel-none-elf-objcopy -O binary -j .text -j .rodata -j .data -j .bss build/jump.elf build/jump.bin
echo "actual jump.bin size: $(wc -c < build/jump.bin)"

gcc src/injector/*.c src/injector/*.h -o build/injector.elf
./build/injector.elf "$target_ver"

truncate -s 8192 build/code.bin
cp build/code.bin build/fs/VIDEO_TS/VIDEO_TS.BUP

genisoimage -dvd-video -V "YADE_$target_ver" -o build/exploit.iso build/fs/
