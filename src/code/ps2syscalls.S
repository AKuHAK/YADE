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

syscall_map ExecPS2, 0x07
syscall_map FlushCache, 0x64
syscall_map DeleteThread, 0x21
syscall_map TerminateThread, 0x25
syscall_map ChangeThreadPriority, 0x29
syscall_map GetThreadId, 0x2f
syscall_map CancelWakeupThread, 0x35
syscall_map Exit, 0x04
syscall_map sceSifStopDma, 0x6b
syscall_map sceSifGetReg, 0x7a
syscall_map sceSifSetReg, 0x79
syscall_map sceSifSetDma, 0x77
