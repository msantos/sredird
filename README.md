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
supports RFC 2217.

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

~~~ /etc/udev/rules.d/10-usb-serial.rules
SUBSYSTEM=="tty", ATTRS{idProduct}=="6001", ATTRS{idVendor}=="0403", ATTRS{serial}=="FTG9GBNY", SYMLINK+="console@getpid"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2008", ATTRS{idVendor}=="0557", SYMLINK+="console@switch"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2303", ATTRS{idVendor}=="067b", ATTRS{version}==" 1.10", SYMLINK+="console@getsid"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2303", ATTRS{idVendor}=="067b", ATTRS{version}==" 2.00", SYMLINK+="console@sigquit"
~~~

## service run

* service/console@getpid/run

~~~
#!/bin/bash

umask 077

mkdir -p /tmp/sredird

exec 2>&1
exec unixexec /tmp/sredird/console@getpid \
  hexlog none \
  sredird -t 900 5 /dev/console@getpid
~~~

## service run log

* service/console@getpid/log/run

~~~
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SERVICE="$(basename $(dirname $PWD))"
exec tscat -o 2 "$SERVICE"
~~~

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

    # clone the kernel headers somewhere
    cd /path/to/dir
    git clone https://github.com/sabotage-linux/kernel-headers.git

    # then compile
    MUSL_INCLUDE=/path/to/dir ./musl-make clean all

# ALTERNATIVES
