/* Copyright (c) 2020-2021, Michael Santos <michael.santos@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "restrict_process.h"

#ifdef RESTRICT_PROCESS_capsicum
#include <sys/types.h>

#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

#include <errno.h>

int restrict_process_init(void) {
  struct rlimit rl = {0};

  /* Disable forking */
  return setrlimit(RLIMIT_NPROC, &rl);
}

int restrict_process_stdio(int devicefd) {
  struct rlimit rl = {0};
  cap_rights_t policy_read;
  cap_rights_t policy_write;
  cap_rights_t policy_rw;
  const unsigned long iocmd[] = {
      TIOCGETA,
      TIOCSETA,
      TIOCSETAW,
      TIOCGWINSZ,
  };

  /* Disables opening new file descriptors */
  if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
    return -1;

  if (cap_enter() != 0)
    return -1;

  (void)cap_rights_init(&policy_read, CAP_READ, CAP_EVENT);
  (void)cap_rights_init(&policy_write, CAP_WRITE, CAP_EVENT);
  (void)cap_rights_init(&policy_rw, CAP_READ, CAP_EVENT, CAP_WRITE, CAP_FSTAT,
                        CAP_FCNTL, CAP_IOCTL);

  if (cap_rights_limit(STDIN_FILENO, &policy_read) < 0)
    return -1;

  if (cap_rights_limit(STDOUT_FILENO, &policy_write) < 0)
    return -1;

  if (cap_rights_limit(STDERR_FILENO, &policy_write) < 0)
    return -1;

  /* serial device */
  if (cap_rights_limit(devicefd, &policy_rw) < 0)
    return -1;

  if (cap_ioctls_limit(devicefd, iocmd, sizeof(iocmd)) < 0)
    return -1;

  if (cap_fcntls_limit(devicefd, CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) < 0)
    return -1;

  return 0;
}
#endif
