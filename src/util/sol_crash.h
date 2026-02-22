/*
 * sol_crash.h - Best-effort crash handlers (stack traces)
 */

#ifndef SOL_CRASH_H
#define SOL_CRASH_H

/* Install SIGSEGV/SIGABRT/etc handlers that print a best-effort stack trace to
 * stderr before terminating the process. */
void sol_crash_install_handlers(void);

#endif /* SOL_CRASH_H */

