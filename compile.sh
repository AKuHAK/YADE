#!/bin/bash
set -e

target_ver=$1
[[ -z "$target_ver" ]] && target_ver="3.00"

echo "=== Building Universal ISO for Major Version: $target_ver ==="

mkdir -p build

# Флаги компиляции
CFLAGS="-Os -march=r5900 -mabi=eabi -ffreestanding -nostdlib -G0 -fno-pic -mno-abicalls"

# 1. Сборка основного кода (payload)
mipsel-none-elf-gcc $CFLAGS \
    -Isrc/code \
    -DBOOT_FILE_SIZE=$(wc -c < fs/BOOT.ELF) \
    -T src/ld/code.ld \
    -o build/code.elf \
    src/code/*.c src/code/*.S

mipsel-none-elf-objcopy -O binary build/code.elf build/code.bin

# 2. Сборка универсального загрузчика (jump)
# ВАЖНО: Добавляем src/code/ps2cstd.c для поддержки memcpy/memset
mipsel-none-elf-gcc $CFLAGS \
    -Isrc/jump -Isrc/code \
    -T src/ld/jump.ld \
    -o build/jump.elf \
    src/jump/*.c src/jump/*.S src/code/ps2cstd.c

mipsel-none-elf-objcopy -O binary build/jump.elf build/jump.bin

# 3. Сборка инжектора
gcc -Isrc/injector -Isrc/code src/injector/*.c src/code/pgc.c -o build/injector.elf

# 4. Создание ISO
rm -rf build/fs
cp -r fs build/fs
./build/injector.elf "$target_ver"

truncate -s 8192 build/code.bin
cp build/code.bin build/fs/VIDEO_TS/VIDEO_TS.BUP
genisoimage -dvd-video -V "YADE" -o build/exploit.iso build/fs/