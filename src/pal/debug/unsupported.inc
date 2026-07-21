
bool pal_debug_supported(void) { return false; }
bool pal_debug_fpregs_supported(void) { return false; }
bool pal_debug_fsgsbase_supported(void) { return false; }

long pal_debug_ptrace(int op, int pid, void *addr, long data) {
  (void)op;
  (void)pid;
  (void)addr;
  (void)data;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_wait(int pid, int *status, bool nohang) {
  (void)pid;
  (void)status;
  (void)nohang;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_attach(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_detach(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_continue(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_syscall(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}

int pal_debug_stop(int pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
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

int pal_debug_get_regs(int pid, int32_t lwp, memdbg_debug_regs_t *regs) {
  (void)pid;
  (void)lwp;
  (void)regs;
  errno = ENOTSUP;
  return -1;
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

