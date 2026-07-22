/* Regression test: PS4 SDKs also identify as FreeBSD, but socket waits must
 * use select rather than the desktop kqueue implementation. */

#include "memdbg/pal/pal_wait.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if !defined(MEMDBG_PAL_PLATFORM_PS4)
#error "test must be compiled with PLATFORM_PS4"
#endif

#if !defined(MEMDBG_PAL_WAIT_BACKEND_SELECT)
#error "PS4 must select the select() wait backend"
#endif

#if defined(MEMDBG_PAL_WAIT_BACKEND_EPOLL) || \
    defined(MEMDBG_PAL_WAIT_BACKEND_KQUEUE)
#error "PS4 must not select a desktop wait backend"
#endif

int main(void) {
  int sockets[2];
  const char byte = 'x';

  if (strcmp(MEMDBG_PAL_WAIT_BACKEND_NAME, "select") != 0) return 1;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
    perror("socketpair");
    return 1;
  }
  if (wait_for_client(sockets[0], 0) != 0 ||
      write(sockets[1], &byte, sizeof(byte)) != (ssize_t)sizeof(byte) ||
      wait_for_client(sockets[0], 100) != 1) {
    fputs("PS4 select() wait path failed\n", stderr);
    (void)close(sockets[0]);
    (void)close(sockets[1]);
    return 1;
  }
  (void)close(sockets[0]);
  (void)close(sockets[1]);
  puts("PS4 wait backend: select (PASS)");
  return 0;
}
