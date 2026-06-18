#!/bin/bash
set -e

target_ver=$1
[[ -z "$target_ver" ]] && target_ver="3.00"

echo "=== Building Universal ISO for Major Version: $target_ver ==="

rm -rf build
mkdir -p build

# Флаги компиляции: 
# -G0 отключает использование малых секций данных (фикс R_MIPS_GPREL16)
# -fno-pic и -mno-abicalls важны для "голого" железа
CFLAGS="-Os -march=r5900 -mabi=eabi -ffreestanding -nostdlib -G0 -fno-pic -mno-abicalls"

# 1. Сборка основного кода
mipsel-none-elf-gcc $CFLAGS \
    -Isrc/code \
    -DBOOT_FILE_SIZE=$(wc -c < fs/BOOT.ELF) \
    -T src/ld/code.ld \
    -o build/code.elf \
    src/code/*.c src/code/*.S

mipsel-none-elf-objcopy -O binary build/code.elf build/code.bin

# 2. Сборка универсального загрузчика
mipsel-none-elf-gcc $CFLAGS \
    -Isrc/jump \
    -T src/ld/jump.ld \
    -o build/jump.elf \
    src/jump/*.c src/jump/*.S

mipsel-none-elf-objcopy -O binary build/jump.elf build/jump.bin

# 3. Сборка инжектора (нативный GCC)
gcc -Isrc/injector src/injector/*.c src/injector/*.h -o build/injector.elf

# Подготовка структуры папок для ISO
cp -r fs build/fs

# Запуск инжектора, который создаст несколько VTS файлов под разные регионы
./build/injector.elf "$target_ver"

# Финализация образа
truncate -s 8192 build/code.bin
cp build/code.bin build/fs/VIDEO_TS/VIDEO_TS.BUP
genisoimage -dvd-video -V "YADE_$target_ver" -o build/exploit.iso build/fs/

echo "Build successful for $target_ver"