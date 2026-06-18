#!/bin/bash
set -e

target_ver=$1
[[ -z "$target_ver" ]] && target_ver="3.00"

echo "=== Building Universal PS2 Exploit [$target_ver] ==="

mkdir -p build

mipsel-none-elf-gcc -Os -march=r5900 -mabi=eabi -ffreestanding -nostdlib \
    -Isrc/code -T src/ld/code.ld -o build/code.elf src/code/*.c src/code/*.S
mipsel-none-elf-objcopy -O binary build/code.elf build/code.bin

mipsel-none-elf-gcc -Os -march=r5900 -mabi=eabi -ffreestanding -nostdlib \
    -Isrc/jump -T src/ld/jump.ld -o build/jump.elf src/jump/*.c src/jump/*.S
mipsel-none-elf-objcopy -O binary build/jump.elf build/jump.bin

gcc -Isrc/injector src/injector/*.c -o build/injector.elf
rm -rf build/fs
cp -r fs build/fs
./build/injector.elf "$target_ver"

truncate -s 8192 build/code.bin
cp build/code.bin build/fs/VIDEO_TS/VIDEO_TS.BUP
genisoimage -dvd-video -V "YADE" -o "release/exploit_$target_ver.iso" build/fs/

echo "Done: release/exploit_$target_ver.iso"