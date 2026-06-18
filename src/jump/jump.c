typedef int (*readBufferInternal_t)(char *, int, int, void *, int, int);
typedef void (*code_t)(void);


static inline int GetThreadId(void) {
    register int v0 asm("v0");
    asm volatile ("li $v1, 0x2f\nsyscall\n" : "=r"(v0) : : "v1", "memory");
    return v0;
}
static inline void ChangeThreadPriority(int thread_id, int priority) {
    register int a0 asm("a0") = thread_id;
    register int a1 asm("a1") = priority;
    asm volatile ("li $v1, 0x29\nsyscall\n" : : "r"(a0), "r"(a1) : "v1", "memory");
}
static inline int CancelWakeupThread(int thread_id) {
    register int v0 asm("v0");
    register int a0 asm("a0") = thread_id;
    asm volatile ("li $v1, 0x35\nsyscall\n" : "=r"(v0) : "r"(a0) : "v1", "memory");
    return v0;
}
static inline void TerminateThread(int thread_id) {
    register int a0 asm("a0") = thread_id;
    asm volatile ("li $v1, 0x25\nsyscall\n" : : "r"(a0) : "v1", "memory");
}
static inline void DeleteThread(int thread_id) {
    register int a0 asm("a0") = thread_id;
    asm volatile ("li $v1, 0x21\nsyscall\n" : : "r"(a0) : "v1", "memory");
}
static inline void FlushCache(int mode) {
    register int a0 asm("a0") = mode;
    asm volatile ("li $v1, 0x64\nsyscall\n" : : "r"(a0) : "v1", "memory");
}

int main(void) {
    int tid = GetThreadId();
    ChangeThreadPriority(tid, 0);
    CancelWakeupThread(tid);
    for (int i = 1; i < 256; ++i) {
        if(i != tid) {
            TerminateThread(i);
            DeleteThread(i);
        }
    }

    readBufferInternal_t readBufferInternal = (readBufferInternal_t)0;


    unsigned int *v_addrs[] = {
        (unsigned int *)0x009091a0, (unsigned int *)0x009090a0, (unsigned int *)0x00684920,
        (unsigned int *)0x0090c310, (unsigned int *)0x006ee290, (unsigned int *)0x00678410,
        (unsigned int *)0x00683d90, (unsigned int *)0x00685f10, (unsigned int *)0x00682810,
        (unsigned int *)0x0090c210, (unsigned int *)0x00923d10, (unsigned int *)0x0069de10,
        (unsigned int *)0x0095ac70, (unsigned int *)0x006d4df0
    };

    unsigned int rbi_addrs[] = {
        0x00244438, 0x00244378, 0x00244018, 0x002566d8, 0x002566b8, 0x002566b8,
        0x002566b8, 0x00256330, 0x002566a8, 0x00256668, 0x00262360, 0x00262340,
        0x00261548, 0x00261560
    };

    for (int i = 0; i < 14; i++) {
        if (v_addrs[i][0] == 0x45444956) { // "VIDE"
            readBufferInternal = (readBufferInternal_t)rbi_addrs[i];
            break;
        }
    }

    if (readBufferInternal) {
        code_t code = (code_t)((void *)(0x2000000 - (0x800 * 3)));
        readBufferInternal("", 0, 4, code, 2, 0);
        FlushCache(0);
        FlushCache(2);
        code();
    }
    return 0;
}