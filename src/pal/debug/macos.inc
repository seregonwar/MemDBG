
/*
 * macOS implementation.
 * Uses ptrace(PT_ATTACHEXC, ...) for attach / crash notification and
 * Mach task_for_pid + thread_get_state for register access.
 * PT_SYSCALL is not available on macOS, so syscall tracing is not supported.
 */

#include <sys/ptrace.h>
#include <mach/mach.h>
#include <mach/thread_status.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <dlfcn.h>
#include <unistd.h>

#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif

bool pal_debug_supported(void) { return true; }
bool pal_debug_fpregs_supported(void) { return false; }
bool pal_debug_fsgsbase_supported(void) { return false; }

long pal_debug_ptrace(int op, int pid, void *addr, long data) {
  return ptrace(op, pid, (caddr_t)addr, (int)data);
}

static void pal_debug_sleep_ms(uint32_t ms) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
}

int pal_debug_wait(int pid, int *status, bool nohang) {
  int st = 0;
  if (status == NULL) status = &st;
  int flags = nohang ? WNOHANG : 0;
  pid_t r = waitpid((pid_t)pid, status, flags);
  if (r == -1) return -1;
  if (nohang && r == 0) {
    *status = 0;
    return 0;
  }
  return 1;
}

int pal_debug_attach(int pid) {
  /* On macOS, PT_ATTACHEXC attaches and routes exceptions through Mach
   * exception ports. The target receives SIGSTOP. */
  if (ptrace(PT_ATTACHEXC, pid, 0, 0) == -1) return -1;

  for (int i = 0; i < 500; ++i) {
    int status = 0;
    int r = pal_debug_wait(pid, &status, true);
    if (r == 1 && WIFSTOPPED(status)) return 0;
    if (r == -1 && errno != EINTR) break;
    pal_debug_sleep_ms(10U);
  }

  (void)pal_debug_detach(pid);
  errno = ETIMEDOUT;
  return -1;
}

int pal_debug_detach(int pid) {
  return (ptrace(PT_DETACH, pid, 0, 0) == -1) ? -1 : 0;
}

int pal_debug_continue(int pid) {
  return (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) == -1) ? -1 : 0;
}

int pal_debug_syscall(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_stop(int pid) {
  return (kill((pid_t)pid, SIGSTOP) == 0) ? 0 : -1;
}

int pal_debug_single_step(int pid, int32_t lwp) {
  (void)pid;
  (void)lwp;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_suspend_thread(int pid, int32_t lwp) {
  (void)pid;
  (void)lwp;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_resume_thread(int pid, int32_t lwp) {
  (void)pid;
  (void)lwp;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_count(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_list(int pid, int32_t *lwps, int max_count) {
  (void)pid;
  (void)lwps;
  (void)max_count;
  errno = ENOTSUP;
  return -1;
}

/* Helper: convert thread state (macOS) to memdbg_debug_regs_t. */
#if defined(__x86_64__)
static void pal_debug_regs_from_native(const x86_thread_state64_t *src,
                                      memdbg_debug_regs_t *dst) {
  memset(dst, 0, sizeof(*dst));
  dst->r_rax  = (int64_t)src->__rax;
  dst->r_rbx  = (int64_t)src->__rbx;
  dst->r_rcx  = (int64_t)src->__rcx;
  dst->r_rdx  = (int64_t)src->__rdx;
  dst->r_rdi  = (int64_t)src->__rdi;
  dst->r_rsi  = (int64_t)src->__rsi;
  dst->r_rbp  = (int64_t)src->__rbp;
  dst->r_rsp  = (int64_t)src->__rsp;
  dst->r_r8   = (int64_t)src->__r8;
  dst->r_r9   = (int64_t)src->__r9;
  dst->r_r10  = (int64_t)src->__r10;
  dst->r_r11  = (int64_t)src->__r11;
  dst->r_r12  = (int64_t)src->__r12;
  dst->r_r13  = (int64_t)src->__r13;
  dst->r_r14  = (int64_t)src->__r14;
  dst->r_r15  = (int64_t)src->__r15;
  dst->r_rip  = (int64_t)src->__rip;
  dst->r_rflags = (int64_t)src->__rflags;
  dst->r_cs   = (int64_t)src->__cs;
  dst->r_fs   = (uint16_t)src->__fs;
  dst->r_gs   = (uint16_t)src->__gs;
}
#elif defined(__arm64__) || defined(__aarch64__)
static void pal_debug_regs_from_native(const arm_thread_state64_t *src,
                                      memdbg_debug_regs_t *dst) {
  memset(dst, 0, sizeof(*dst));
  /* Map ARM64 x0-x13 to x86-style slots for crash dump utility.
   * The struct __x[] array is accessible even in the opaque layout. */
  dst->r_rax  = (int64_t)src->__x[0];
  dst->r_rbx  = (int64_t)src->__x[1];
  dst->r_rcx  = (int64_t)src->__x[2];
  dst->r_rdx  = (int64_t)src->__x[3];
  dst->r_rdi  = (int64_t)src->__x[4];
  dst->r_rsi  = (int64_t)src->__x[5];
  dst->r_r8   = (int64_t)src->__x[6];
  dst->r_r9   = (int64_t)src->__x[7];
  dst->r_r10  = (int64_t)src->__x[8];
  dst->r_r11  = (int64_t)src->__x[9];
  dst->r_r12  = (int64_t)src->__x[10];
  dst->r_r13  = (int64_t)src->__x[11];
  dst->r_r14  = (int64_t)src->__x[12];
  dst->r_r15  = (int64_t)src->__x[13];
  dst->r_rbp  = (int64_t)__darwin_arm_thread_state64_get_fp(*src);
  dst->r_rsp  = (int64_t)__darwin_arm_thread_state64_get_sp(*src);
  dst->r_rip  = (int64_t)__darwin_arm_thread_state64_get_pc(*src);
  dst->r_rflags = (int64_t)src->__cpsr & 0xffffffff;
  dst->r_cs   = 0;  /* not available on ARM64 */
  dst->r_fs   = 0;
  dst->r_gs   = 0;
}
#endif

int pal_debug_get_regs(int pid, int32_t lwp, memdbg_debug_regs_t *regs) {
  (void)lwp;
  task_t task = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  if (kr != KERN_SUCCESS) {
    return -1;
  }

  /* Get thread list from the task. */
  thread_act_array_t threads;
  mach_msg_type_number_t thread_count;
  kr = task_threads(task, &threads, &thread_count);
  if (kr != KERN_SUCCESS) {
    mach_port_deallocate(mach_task_self(), task);
    return -1;
  }

  if (thread_count == 0) {
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                       thread_count * sizeof(thread_t));
    mach_port_deallocate(mach_task_self(), task);
    return -1;
  }

  /* Read registers from the first thread (crash thread is typically first). */
#if defined(__x86_64__)
  x86_thread_state64_t state;
  mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
  kr = thread_get_state(threads[0], x86_THREAD_STATE64,
                        (thread_state_t)&state, &state_count);
#elif defined(__arm64__) || defined(__aarch64__)
  arm_thread_state64_t state;
  mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
  kr = thread_get_state(threads[0], ARM_THREAD_STATE64,
                        (thread_state_t)&state, &state_count);
#endif
  if (kr != KERN_SUCCESS) {
    for (mach_msg_type_number_t i = 0; i < thread_count; i++)
      mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                       thread_count * sizeof(thread_t));
    mach_port_deallocate(mach_task_self(), task);
    return -1;
  }

  pal_debug_regs_from_native(&state, regs);

  for (mach_msg_type_number_t i = 0; i < thread_count; i++)
    mach_port_deallocate(mach_task_self(), threads[i]);
  vm_deallocate(mach_task_self(), (vm_address_t)threads,
                     thread_count * sizeof(thread_t));
  mach_port_deallocate(mach_task_self(), task);
  return 0;
}

int pal_debug_set_regs(int pid, int32_t lwp, const memdbg_debug_regs_t *regs) {
  (void)pid;
  (void)lwp;
  (void)regs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_fpregs(int pid, int32_t lwp,
                         memdbg_debug_fpregs_t *fpregs) {
  (void)pid;
  (void)lwp;
  if (fpregs != NULL) memset(fpregs, 0, sizeof(*fpregs));
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_fpregs(int pid, int32_t lwp,
                         const memdbg_debug_fpregs_t *fpregs) {
  (void)pid;
  (void)lwp;
  (void)fpregs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_fsgsbase(int pid, int32_t lwp,
                           memdbg_debug_fsgsbase_t *base) {
  (void)pid;
  (void)lwp;
  if (base != NULL) memset(base, 0, sizeof(*base));
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_fsgsbase(int pid, int32_t lwp,
                           const memdbg_debug_fsgsbase_t *base) {
  (void)pid;
  (void)lwp;
  (void)base;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_dbregs(int pid, int32_t lwp,
                         memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
  (void)lwp;
  (void)dbregs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_set_dbregs(int pid, int32_t lwp,
                         const memdbg_debug_dbregs_t *dbregs) {
  (void)pid;
  (void)lwp;
  (void)dbregs;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_name(int pid, int32_t lwp, char *name,
                              size_t name_len) {
  (void)pid;
  (void)lwp;
  if (name != NULL && name_len > 0) name[0] = '\0';
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_state(int pid, int32_t lwp, int *state_out) {
  (void)pid;
  (void)lwp;
  if (state_out != NULL) *state_out = (int)MEMDBG_THREAD_UNKNOWN;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_stop_info(int pid, int32_t lwp,
                                   int *pl_event, int *stop_signal,
                                   int *pl_flags,
                                   uint64_t *pl_sigmask_lo,
                                   uint64_t *pl_sigmask_hi,
                                   uint64_t *pl_siglist_lo,
                                   uint64_t *pl_siglist_hi) {
  (void)pid; (void)lwp; (void)pl_event; (void)stop_signal; (void)pl_flags;
  (void)pl_sigmask_lo; (void)pl_sigmask_hi;
  (void)pl_siglist_lo; (void)pl_siglist_hi;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_get_thread_extra_info(int pid, const int32_t *lwps, uint32_t count,
                                    int *priorities, uint64_t *runtimes_us,
                                    int *pctcpus, int *cpu_ids) {
  (void)pid; (void)lwps; (void)count;
  (void)priorities; (void)runtimes_us; (void)pctcpus; (void)cpu_ids;
  errno = ENOTSUP;
  return -1;
}

