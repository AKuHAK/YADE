typedef int (*readBufferInternal_t)(char *, int, int, void *, int, int);
typedef void (*code_t)(void);

static inline int GetThreadId(void) {
    register int v0 asm("v0");
    asm volatile("li $v1, 0x2f\nsyscall\n" : "=r"(v0) :: "v1", "memory");
    return v0;
}
static inline void ChangeThreadPriority(int id, int pri) {
    register int a0 asm("a0") = id;
    register int a1 asm("a1") = pri;
    asm volatile("li $v1, 0x29\nsyscall\n" :: "r"(a0), "r"(a1) : "v1", "memory");
}
static inline void CancelWakeupThread(int id) {
    register int a0 asm("a0") = id;
    asm volatile("li $v1, 0x35\nsyscall\n" :: "r"(a0) : "v1", "memory");
}
static inline void TerminateThread(int id) {
    register int a0 asm("a0") = id;
    asm volatile("li $v1, 0x25\nsyscall\n" :: "r"(a0) : "v1", "memory");
}
static inline void DeleteThread(int id) {
    register int a0 asm("a0") = id;
    asm volatile("li $v1, 0x21\nsyscall\n" :: "r"(a0) : "v1", "memory");
}
static inline void FlushCache(int mode) {
    register int a0 asm("a0") = mode;
    asm volatile("li $v1, 0x64\nsyscall\n" :: "r"(a0) : "v1", "memory");
}

int main(void) {
    int tid = GetThreadId();
    ChangeThreadPriority(tid, 0);
    CancelWakeupThread(tid);
    for (int i = 1; i < 256; ++i) {
        if (i != tid) {
            TerminateThread(i);
            DeleteThread(i);
        }
    }

    readBufferInternal_t readBufferInternal = (readBufferInternal_t)0;

    /* Detect version at runtime: check for "VIDE" magic at known per-version addresses.
     * Each address is VM_CMD_PARSER_SWITCH_ADDR - 0x68 for the given DVD player build.
     * Using an if-else chain with immediate constants avoids any .rodata references,
     * making this code position-independent regardless of load address. */
    if      (*(volatile unsigned int *)0x009091a0u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00244438u; /* 3.00E */
    else if (*(volatile unsigned int *)0x009090a0u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00244378u; /* 3.00U */
    else if (*(volatile unsigned int *)0x00684920u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00244018u; /* 3.00J */
    else if (*(volatile unsigned int *)0x0090c310u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x002566d8u; /* 3.02E */
    else if (*(volatile unsigned int *)0x006ee290u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x002566b8u; /* 3.02C */
    else if (*(volatile unsigned int *)0x00678410u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x002566b8u; /* 3.02D */
    else if (*(volatile unsigned int *)0x00683d90u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x002566b8u; /* 3.02G */
    else if (*(volatile unsigned int *)0x00685f10u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00256330u; /* 3.02J */
    else if (*(volatile unsigned int *)0x00682810u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x002566a8u; /* 3.02K */
    else if (*(volatile unsigned int *)0x0090c210u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00256668u; /* 3.02U */
    else if (*(volatile unsigned int *)0x00923d10u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00262360u; /* 3.03E */
    else if (*(volatile unsigned int *)0x0069de10u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00262340u; /* 3.03J */
    else if (*(volatile unsigned int *)0x0095ac70u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00261548u; /* 3.04M */
    else if (*(volatile unsigned int *)0x006d4df0u == 0x45444956u) readBufferInternal = (readBufferInternal_t)0x00261560u; /* 3.04J */

    if (readBufferInternal) {
        char dummy = 0;
        code_t code = (code_t)(0x2000000u - 0x1800u);
        readBufferInternal(&dummy, 0, 4, (void *)code, 2, 0);
        FlushCache(0);
        FlushCache(2);
        code();
    }
    return 0;
}
