#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "psmkit-io.h"

int sceKernelDebugOutText(int channel, const char *text);

/* Crash forensics for the B1 title: the console's MDBG error view keeps no
 * history, so the process records its own story. Every io_log line is appended
 * to /data/anocore/pw-io.log, so the LAST line on disk names the boot stage
 * that was running when the process died, even when the kernel log ring is
 * unreadable. A fatal SIGSYS got a black box: the raw signal words are
 * appended to /data/anocore/last-crash.txt, and the signal is swallowed up to
 * a small budget so the rejected-stage boot continues and shows how much
 * further the sandbox reaches. Writes are best effort: absent or unwritable
 * frames never turn a diagnostic file into a start failure. */
#define PW_IO_BBOX_PATH "/data/anocore/pw-io.log"
#define PW_IO_CRASH_PATH "/data/anocore/last-crash.txt"
#define PW_IO_BBOX_BUDGET 32
#define PW_IO_BBOX_COOLDOWN 256

/* One descriptor for the run log, and an open retry period for the tree the
 * writebroker repairs later. O_APPEND keeps concurrent threads' lines intact
 * in practice; a torn tail costs one line, never the file. */
static void io_blackbox_fd(int *descriptor, const char *path, unsigned int *cooldown)
{
    if (*descriptor == -1)
    {
        if (++*cooldown < PW_IO_BBOX_COOLDOWN) return;
        *cooldown = 0;
    }
    *descriptor = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (*descriptor < 0) *descriptor = -1;
}

void io_blackbox_line(const char *line, size_t length)
{
    static int fd = -2;
    static unsigned int cooldown;
    struct timespec stamp;
    char stamped[600];
    int head;

    io_blackbox_fd(&fd, PW_IO_BBOX_PATH, &cooldown);
    if (fd < 0) return;
    if (length > sizeof(stamped) - 1) length = sizeof(stamped) - 1;
    if (clock_gettime(CLOCK_REALTIME, &stamp))
    {
        memcpy(stamped, line, length);
        head = (int)length;
    }
    else
    {
        head = snprintf(stamped, sizeof(stamped), "%05lld %.*s",
                        (long long)(stamp.tv_sec % 100000) * 1000 + stamp.tv_nsec / 1000000,
                        (int)length, line);
        if (head < 0 || head >= (int)sizeof(stamped))
        {
            memcpy(stamped, line, length);
            head = (int)length;
        }
    }
    (void)write(fd, stamped, (size_t)head);
}

void io_log(const char *format, ...)
{
    char line[512];
    va_list args;
    va_start(args, format);
    vsnprintf(line, sizeof(line) - 2, format, args);
    va_end(args);
    strcat(line, "\n");
    sceKernelDebugOutText(0, line);
    io_blackbox_line(line, strlen(line));
}

/* Raw siginfo words: the console's layout is the kernel's, whose fields for a
 * rejected call (code, call address, syscall number) live in the union past
 * si_addr; instead of guessing the offsets, dump the first words verbatim and
 * let the reader compare consecutive events. */
static void pw_io_blackbox_signal(int signal_number, siginfo_t *info, void *context)
{
    (void)context;
    static int events;
    int count = ++events;
    const unsigned int *raw = (const unsigned int *)info;
    char line[560];
    int length;

    if (info)
    {
        length = snprintf(line, sizeof(line),
                          "fatal sig=%d code=%d errno=%d pid=%lu uid=%lu words=%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
                          signal_number, info->si_code, info->si_errno,
                          (unsigned long)info->si_pid, (unsigned long)info->si_uid,
                          raw[3], raw[4], raw[5], raw[6], raw[7], raw[8],
                          raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
    }
    else
        length = snprintf(line, sizeof(line), "fatal sig=%d code=0 no-siginfo\n", signal_number);
    if (length < 0 || length >= (int)sizeof(line)) length = (int)sizeof(line) - 1;
    {
        static int fd = -2;
        static unsigned int cooldown;
        io_blackbox_fd(&fd, PW_IO_CRASH_PATH, &cooldown);
        if (fd >= 0) (void)write(fd, line, (size_t)length);
    }
    (void)io_log("fatal sig=%d events=%d code=%d errno=%d pid=%ld uid=%ld",
                 signal_number, count, info ? info->si_code : 0,
                 info ? info->si_errno : 0,
                 (long)(info ? info->si_pid : 0), (long)(info ? info->si_uid : 0));
    /* Past the budget, stop hiding the signal: restore the default action so
     * a looping policy rejection still ends the process the normal way. */
    if (count > PW_IO_BBOX_BUDGET)
    {
        struct sigaction restore;
        memset(&restore, 0, sizeof(restore));
        restore.sa_handler = SIG_DFL;
        sigemptyset(&restore.sa_mask);
        (void)sigaction(signal_number, &restore, NULL);
        (void)kill(getpid(), signal_number);
    }
}

void io_signal_blackbox_install(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = pw_io_blackbox_signal;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSYS, &action, NULL))
        io_log("blackbox: SIGSYS sigaction failed errno=%d", errno);
}

int64_t io_now_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Partial stream IO and EINTR stay within the ORIGINAL operation deadline;
 * they are not another launch/exchange attempt. Never block in send/recv. */
int io_transfer(int fd, void *buffer, size_t size, int writing, int64_t overall_deadline)
{
    int64_t now = io_now_ms();
    if (now < 0) return -1;
    int64_t deadline = now + IO_OPERATION_MS;
    if (deadline > overall_deadline) deadline = overall_deadline;
    unsigned char *bytes = buffer;
    size_t done = 0;
    while (done < size)
    {
        now = io_now_ms();
        if (now < 0) return -1;
        if (now >= deadline)
        {
            errno = ETIMEDOUT;
            return -1;
        }
        struct pollfd descriptor = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        int result = poll(&descriptor, 1, (int)(deadline - now));
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -1;
        if (!result)
        {
            errno = ETIMEDOUT;
            return -1;
        }
        if (descriptor.revents & POLLNVAL)
        {
            errno = EBADF;
            return -1;
        }
        ssize_t count = writing ? send(fd, bytes + done, size - done, MSG_DONTWAIT | MSG_NOSIGNAL)
                                : recv(fd, bytes + done, size - done, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count < 0) return -1;
        if (!count)
        {
            errno = 0;
            return 1; /* orderly EOF, distinct from a socket error */
        }
        done += (size_t)count;
    }
    now = io_now_ms();
    if (now < 0) return -1;
    if (now >= deadline)
    {
        errno = ETIMEDOUT;
        return -1;
    }
    return 0;
}

uint32_t io_expected_checksum(void)
{
    uint32_t checksum = UINT32_C(2166136261);
    for (size_t page = 0; page < IO_PAGES; page++)
        checksum = (checksum ^ io_page_byte(page)) * UINT32_C(16777619);
    return checksum;
}
