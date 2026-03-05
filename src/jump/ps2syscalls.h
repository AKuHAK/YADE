#ifndef YADE_PS2SYSCALLS
#define YADE_PS2SYSCALLS

extern void FlushCache(int mode);
extern void DeleteThread(int thread_id);
extern void TerminateThread(int thread_id);
extern void ChangeThreadPriority(int thread_id, int priority);
extern int GetThreadId(void);
extern int CancelWakeupThread(int thread_id);
extern int Exit(int status);

#endif
