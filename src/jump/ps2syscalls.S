.set noreorder
.section .text

.macro syscall_map name, idn
    .global \name
    .type \name, @function
    \name:
        li  $v1, \idn
        syscall
        jr $ra
        nop
.endm

syscall_map FlushCache, 0x64
syscall_map DeleteThread, 0x21
syscall_map TerminateThread, 0x25
syscall_map ChangeThreadPriority, 0x29
syscall_map GetThreadId, 0x2f
syscall_map CancelWakeupThread, 0x35
