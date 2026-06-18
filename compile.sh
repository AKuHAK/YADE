#!/bin/bash
set -e

target_ver=$1
[[ -z "$target_ver" ]] && target_ver="3.00"

echo "=== Building Universal ISO for Major Version: $target_ver ==="

# Создаем папку для сборки и релизов
mkdir -p build
mkdir -p release

# Флаги компиляции для PS2 (MIPS)
# -G0 исправляет ошибку "small-data section too large"
CFLAGS="-Os -march=r5900 -mabi=eabi -ffreestanding -nostdlib -G0 -fno-pic -mno-abicalls"

echo "1. Compiling Main Payload (code.bin)..."
mipsel-none-elf-gcc $CFLAGS \
    -Isrc/code \
    -DBOOT_FILE_SIZE=$(wc -c < fs/BOOT.ELF) \
    -T src/ld/code.ld \
    -o build/code.elf \
    src/code/*.c src/code/*.S

mipsel-none-elf-objcopy -O binary build/code.elf build/code.bin

echo "2. Compiling Universal Loader (jump.bin)..."
# Добавляем src/code/ps2cstd.c для функций memcpy/memset
mipsel-none-elf-gcc $CFLAGS \
    -Isrc/jump -Isrc/code \
    -T src/ld/jump.ld \
    -o build/jump.elf \
    src/jump/*.c src/jump/*.S src/code/ps2cstd.c

mipsel-none-elf-objcopy -O binary build/jump.elf build/jump.bin

echo "3. Compiling Native Injector..."
# Собираем все .c файлы в папке инжектора (injector.c + pgc.c)
# Убедитесь, что pgc.c лежит в src/injector/
gcc -O2 -Isrc/injector src/injector/*.c -o build/injector.elf

echo "4. Generating ISO Structure..."
rm -rf build/fs
cp -r fs build/fs

# Запуск инжектора
./build/injector.elf "$target_ver"

# Финализация образа
truncate -s 8192 build/code.bin
cp build/code.bin build/fs/VIDEO_TS/VIDEO_TS.BUP
genisoimage -dvd-video -V "YADE_$target_ver" -o build/exploit.iso build/fs/

echo "=== Success: build/exploit.iso is ready ==="