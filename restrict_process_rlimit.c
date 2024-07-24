/* Copyright (c) 2020-2024, Michael Santos <michael.santos@gmail.com>
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

#ifdef RESTRICT_PROCESS_rlimit
#include <sys/resource.h>
#include <sys/time.h>

int restrict_process_init(void) {
  struct rlimit rl = {0};

  /* Disable forking */
  if (setrlimit(RLIMIT_NPROC, &rl) < 0)
    return -1;

  /* Disable writing to the filesystem */
  return setrlimit(RLIMIT_FSIZE, &rl);
}

int restrict_process_stdio(int devicefd) {
  struct rlimit rl = {0};

  /* Limit to stdin, stdout, stderr and serial device. */
  rl.rlim_cur = devicefd + 1;
  rl.rlim_max = devicefd + 1;

  return setrlimit(RLIMIT_NOFILE, &rl);
}
#endif
