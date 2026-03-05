.set noreorder
.section .text.boot

.global _start
_start:
    lui $sp, 0x7000
    j main
    ori $sp, $sp, 0x4000