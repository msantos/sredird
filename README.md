# SYNOPSIS

sredird *option* *loglevel* *device* [*pollinginterval*]

# DESCRIPTION

sredird is:

* an [RFC 2217](https://datatracker.ietf.org/doc/html/rfc2217) compliant
  serial port redirector
* maps a network port to a serial device: serial port parameters are
  configured using an extension to the telnet protocol
* runs under a [UCSPI](http://cr.yp.to/proto/ucspi.txt) or other inetd
  style service such as systemd for process level isolation
* restricts process operations using `seccomp(2)`, `pledge(2)`,
  `capsicum(4)` or `setrlimit(2)`

sredird can be used as a minimal serial console server on a device like
a raspberry pi zero w.

A [picocom](https://github.com/npat-efault/picocom/tree/rfc2217) branch
supports RFC 2217 (with the patch below).

This version of sredird is a fork of [sredird
2.2.1-1.1](https://github.com/msantos/sredird/blob/master/README)
taken from Ubuntu 16.04 (there does not seem to be a canonical source
repository for this project). sredird 2.2.1-1.1 is the last C version:
later versions of sredird (2.2.1-2) switched to C++.

# EXAMPLES

```
apt install daemontools
```

* [unixexec](https://github.com/msantos/unixexec)
* [hexlog](https://github.com/msantos/hexlog)
* [tscat](https://github.com/msantos/tscat)

Here is my setup:

* raspberry pi zero w acting as a console server for other raspberry pi's
* example of setup using unixexec
* TODO: show example xmppbot

## /etc/udev/rules.d/10-usb-serial.rules

```
SUBSYSTEM=="tty", ATTRS{idProduct}=="6001", ATTRS{idVendor}=="0403", ATTRS{serial}=="FTG9GBNY", SYMLINK+="console@getpid"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2008", ATTRS{idVendor}=="0557", SYMLINK+="console@switch"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2303", ATTRS{idVendor}=="067b", ATTRS{version}==" 1.10", SYMLINK+="console@getsid"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2303", ATTRS{idVendor}=="067b", ATTRS{version}==" 2.00", SYMLINK+="console@sigquit"
```

## service run

* service/console@getpid/run

```bash
#!/bin/bash

umask 077

mkdir -p /tmp/sredird

exec 2>&1
exec unixexec /tmp/sredird/console@getpid \
  hexlog none \
  sredird -t 900 5 /dev/console@getpid
```

## service run log

* service/console@getpid/log/run

```bash
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SERVICE="$(basename $(dirname $PWD))"
exec tscat -o 2 "$SERVICE"
```

# USAGE

loglevel
: numeric syslog level, see `syslog(3)`

device
: serial device

pollinginterval
: Poll interval is in milliseconds, default is 100, 0 means no polling

# OPTIONS

-i, --cisco-compatibility
: indicates Cisco IOS Bug compatibility

-t, --timeout *seconds*
:set inactivity timeout

# BUILDING

```bash
make

# selecting process restrictions
RESTRICT_PROCESS=seccomp make clean all

# rlimit
RESTRICT_PROCESS=rlimit make clean all

# disable process restrictions
RESTRICT_PROCESS=null make clean all

#### using musl
# sudo apt install musl-dev musl-tools

RESTRICT_PROCESS=rlimit ./musl-make clean all

## linux seccomp sandbox: requires kernel headers
export MUSL_INCLUDE=/tmp
git clone https://github.com/sabotage-linux/kernel-headers.git $MUSL_INCLUDE/kernel-headers
./musl-make clean all
```

# ALTERNATIVES

# PICOCOM

To use the [picocom](https://github.com/npat-efault/picocom/tree/rfc2217) branch with RFC 2217 protocol support with sredird, apply the following patch and compile:

```bash
git clone -b rfc2217 https://github.com/npat-efault/picocom.git
cd picocom
patch -p1 < picocom.patch
make
```

```patch
diff --git a/Makefile b/Makefile
index 75f3fdb..f3c344f 100644
--- a/Makefile
+++ b/Makefile
@@ -1,5 +1,5 @@
 
-VERSION = 4.0a
+VERSION = 4.0a+0.2.1
 
 #CC ?= gcc
 CPPFLAGS += -DVERSION_STR=\"$(VERSION)\"
@@ -46,9 +46,9 @@ linenoise-1.0/linenoise.o : linenoise-1.0/linenoise.c linenoise-1.0/linenoise.h
 #CPPFLAGS += -DNO_CUSTOM_BAUD
 
 ## Comment these in to enable RFC2217 support
-#CPPFLAGS += -DUSE_RFC2217
-#OBJS += tn2217.o
-#tn2217.o : tn2217.c tn2217.h tncomport.h fdio.h termint.h term.h
+CPPFLAGS += -DUSE_RFC2217
+OBJS += tn2217.o
+tn2217.o : tn2217.c tn2217.h tncomport.h fdio.h termint.h term.h
 
 ## Comment this IN to remove help strings (saves ~ 4-6 Kb).
 #CPPFLAGS += -DNO_HELP
diff --git a/tn2217.c b/tn2217.c
index d54676a..f02b836 100644
--- a/tn2217.c
+++ b/tn2217.c
@@ -129,7 +129,7 @@ struct tn2217_state {
     struct termios termios;     /* Predicted remote com port geometry */
     int modem;                  /* Predicted remote com port signals */
 
-    unsigned char cmdbuf[32];   /* IAC command accumulator */
+    unsigned char cmdbuf[255];  /* IAC command accumulator */
     unsigned char cmdbuflen;
     unsigned int cmdiac : 1;    /* 1 iff last cmdbuf ch is incomplete IAC */
 
```
