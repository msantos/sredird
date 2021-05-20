# SRedird base makefile
# Supplied by Kevin Bertram (kevin@cate.com.au)
#
UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Linux)
    RESTRICT_PROCESS ?= seccomp
else ifeq ($(UNAME_SYS), OpenBSD)
    RESTRICT_PROCESS ?= pledge
else ifeq ($(UNAME_SYS), FreeBSD)
    RESTRICT_PROCESS ?= capsicum
endif

RESTRICT_PROCESS ?= rlimit

CC ?= cc
CFLAGS ?= -O3 -pipe -fomit-frame-pointer \
	-D_FORTIFY_SOURCE=2 -fstack-protector-strong \
	-pie -fPIE \
	-fno-strict-aliasing -fwrapv \
	-DRESTRICT_PROCESS=\"$(RESTRICT_PROCESS)\" \
	-DRESTRICT_PROCESS_$(RESTRICT_PROCESS) \
	$(SREDIRD_CFLAGS)

WFLAGS ?= -Wall -Wextra -W -Wshadow -Wpointer-arith -Wwrite-strings -pedantic \
	-Wformat -Werror=format-security
LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack

PROG= sredird
SRC=sredird.c \
	restrict_process_capsicum.c \
	restrict_process_null.c \
	restrict_process_pledge.c \
	restrict_process_rlimit.c \
	restrict_process_seccomp.c

all: $(PROG)
$(PROG):
	$(CC) -g $(CFLAGS) $(WFLAGS) -o sredird $(SRC) $(LDFLAGS)

clean:
	rm -f sredird
