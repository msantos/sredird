# SRedird base makefile
# Supplied by Kevin Bertram (kevin@cate.com.au)
#
RESTRICT_PROCESS ?= rlimit

CC ?= cc
CFLAGS ?= -O3 -pipe -fomit-frame-pointer \
	-D_FORTIFY_SOURCE=2 -fstack-protector-strong \
	-pie -fPIE \
	-fno-strict-aliasing -fwrapv

WFLAGS ?= -Wall -W -Wshadow -Wpointer-arith -Wwrite-strings -pedantic \
	-Wformat -Werror=format-security
LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack

SRC=sredird.c

sredird:	sredird.c
	$(CC) -g $(CFLAGS) $(WFLAGS) -o sredird $(SRC) $(LDFLAGS)

clean:
	rm -f sredird
