# YADE - Yet Another DVD Exploit

YADE is a PlayStation 2 DVD-based exploit that allows executing custom code on PS2 consoles through a specially crafted DVD ISO. This exploit leverages vulnerabilities in the PS2's DVD player firmware to gain code execution.

## Overview

This exploit works by creating a malicious DVD ISO that exploits a buffer overflow in the PS2 DVD player's Program Chain (PGC) command parser. When the DVD is played, it triggers the vulnerability and executes custom code, which can then load and run ELF files.

### Components

- **code/** - Main payload that loads and executes ELF files from the DVD
  - Reads ELF data from disc sectors
  - Parses ELF headers and loads program segments
  - Initializes the PS2 IOP and executes the loaded ELF
  
- **jump/** - Initial loader code that reads and executes the main payload
  - Kills all running threads to ensure clean execution
  - Reads the main payload from disc sector 3
  - Transfers control to the main payload

- **injector/** - PC-side tool that patches DVD files with exploit data
  - Generates exploit PGC structures
  - Patches VOB and IFO files with payload and exploit addresses
  - Creates the final exploit DVD structure

- **fs/** - DVD filesystem template containing VIDEO_TS structure

## Requirements

### Build Requirements

- `mipsel-none-elf-gcc` - MIPS cross-compiler for PS2 (EE core)
- `mipsel-none-elf-objcopy` - Binary utilities for MIPS
- `gcc` - Native C compiler for the injector tool
- `genisoimage` - ISO 9660 filesystem creation utility

### Target Requirements

- PlayStation 2 console (any model)
- DVD-R or DVD+R disc (or PS2 emulator with ISO support)

## Building

To build the exploit ISO:

```bash
./compile.sh
```

This will:
1. Compile the MIPS code for PS2 (code and jump loaders)
2. Compile the PC-side injector tool
3. Patch the DVD filesystem with exploit data
4. Generate `build/exploit.iso`

The resulting ISO file can be burned to a DVD or used with PS2 emulators.

## Output

After building, you'll find:
- `build/exploit.iso` - The final bootable DVD ISO with the exploit
- `build/code.bin` - Compiled main payload
- `build/jump.bin` - Compiled jump loader
- `build/injector.elf` - PC-side injector tool

## How It Works

1. The PS2 DVD player loads the specially crafted PGC commands
2. A buffer overflow in the command parser overwrites function pointers
3. Control is redirected to the jump loader embedded in the VOB file
4. The jump loader reads and executes the main payload from disc
5. The main payload loads the target ELF from disc and executes it

## Technical Details

### Memory Layout

- **Code Location**: 0x2000000 - 0x1000 (payload load address)
- **Jump Stack**: 0x70004000
- **VM Command Parser**: 0x00909208
- **Control Data**: 0x155cec0

### Disc Layout

- Sector 3: Jump loader (2048 bytes)
- Sectors 110-281: Reserved
- Sectors 391+: Main payload ELF

## Security Notice

This exploit is provided for educational and homebrew purposes only. It should only be used on your own hardware for legitimate purposes such as running homebrew applications or backing up your legally owned games.

## Credits

Developed by AKuHAK and contributors.

## License

This project is provided as-is for educational purposes.
