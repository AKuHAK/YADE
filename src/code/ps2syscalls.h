#ifndef YADE_PS2SYSCALLS
#define YADE_PS2SYSCALLS

typedef struct {
    unsigned int data;
	unsigned int addr;
	unsigned int size;
	unsigned int mode;
} sceSifDmaData;

extern void ExecPS2(void *entry, void *gp, int argc, char **argv);
extern void FlushCache(int mode);
extern void DeleteThread(int thread_id);
extern void TerminateThread(int thread_id);
extern void ChangeThreadPriority(int thread_id, int priority);
extern int GetThreadId(void);
extern int CancelWakeupThread(int thread_id);
extern int Exit(int status);
extern void sceSifStopDma(void);
extern int sceSifGetReg(unsigned int register_num);
extern int sceSifSetReg(unsigned int register_num, int register_value);
extern unsigned int sceSifSetDma(sceSifDmaData *sdd, int len);

#endif
