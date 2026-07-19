.set noreorder
.section .text.boot

.global _start
_start:
    lui $sp, 0x7000
    bal main
    ori $sp, $sp, 0x4000
    addi $a0, $v0, 0
    addi $v1, $zero, 4
    syscall
