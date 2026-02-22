/*
 * sol_crash.c - Best-effort crash handlers (stack traces)
 */

#include "sol_crash.h"

#include <execinfo.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_handling_crash = 0;

static const char*
signal_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGABRT: return "SIGABRT";
        case SIGBUS:  return "SIGBUS";
        case SIGILL:  return "SIGILL";
        case SIGFPE:  return "SIGFPE";
        case SIGTRAP: return "SIGTRAP";
        default:      return "UNKNOWN";
    }
}

static void
crash_handler(int sig, siginfo_t* info, void* uctx) {
    (void)uctx;

    if (g_handling_crash) {
        _exit(128 + sig);
    }
    g_handling_crash = 1;

    char header[256];
    int n = snprintf(header,
                     sizeof(header),
                     "\nFATAL: signal %d (%s) addr=%p\n",
                     sig,
                     signal_name(sig),
                     info ? info->si_addr : NULL);
    if (n > 0) {
        size_t nn = (size_t)n;
        if (nn > sizeof(header)) nn = sizeof(header);
        (void)write(STDERR_FILENO, header, nn);
    }

    void* frames[64];
    int frames_n = backtrace(frames, (int)(sizeof(frames) / sizeof(frames[0])));
    if (frames_n > 0) {
        (void)backtrace_symbols_fd(frames, frames_n, STDERR_FILENO);
    }

    _exit(128 + sig);
}

void
sol_crash_install_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;

    (void)sigaction(SIGSEGV, &sa, NULL);
    (void)sigaction(SIGABRT, &sa, NULL);
    (void)sigaction(SIGBUS, &sa, NULL);
    (void)sigaction(SIGILL, &sa, NULL);
    (void)sigaction(SIGFPE, &sa, NULL);
    (void)sigaction(SIGTRAP, &sa, NULL);
}

