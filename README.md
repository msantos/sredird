# SYNOPSIS

sredird *option* *loglevel* *device* [*pollinginterval*]

# DESCRIPTION

sredird is:

* a [RFC 2217](https://datatracker.ietf.org/doc/html/rfc2217) compliant
  serial port redirector

* maps a network port to a serial device: serial port parameters can be
  changed by using an extension to the telnet protocol

* runs under a [UCSPI](http://cr.yp.to/proto/ucspi.txt) or other inetd
  style services such as systemd for process level isolation

* can restrict process operations using `seccomp(2)`, `pledge(2)`,
  `capsicum(4)` or `setrlimit(2)`

sredird can be used for setting up a minimal serial console server on
a device like a raspberry pi zero w.

A [picocom](https://github.com/npat-efault/picocom/tree/rfc2217) branch
supports RFC 2217.

This version of sredird is a fork of [sredird
2.2.1-1.1](https://github.com/msantos/sredird/blob/master/README)
taken from Ubuntu 16.04 (there does not seem to be a canonical source
repository for this project). sredird 2.2.1-1.1 is the last C version:
later versions of sredird (2.2.1-2) switched to C++.

# SETUP

apt install daemontools ucspi-unix

[closefrom](https://github.com/msantos/closefrom)
[hexlog](https://github.com/msantos/hexlog)
[tscat](https://github.com/msantos/tscat)

[ucspi-unix](https://github.com/bruceg/ucspi-unix/pull/2)

Here is my setup:

    * raspberry pi zero w acting as a console server for other raspberry pi's
    * example of setup using unixserver
    * mention vulnerability in unixserver, usage of closefrom
    * show example xmppbot

~~~ /etc/udev/rules.d/10-usb-serial.rules
SUBSYSTEM=="tty", ATTRS{idProduct}=="6001", ATTRS{idVendor}=="0403", ATTRS{serial}=="FTG9GBNY", SYMLINK+="console@getpid"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2008", ATTRS{idVendor}=="0557", SYMLINK+="console@switch"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2303", ATTRS{idVendor}=="067b", ATTRS{version}==" 1.10", SYMLINK+="console@getsid"
SUBSYSTEM=="tty", ATTRS{idProduct}=="2303", ATTRS{idVendor}=="067b", ATTRS{version}==" 2.00", SYMLINK+="console@sigquit"
~~~

~~~ service/console@getpid
#!/bin/bash

umask 077

mkdir -p /tmp/sredird

exec 2>&1
exec unixserver -m 077 -c 1 /tmp/sredird/console@getpid -- \
  hexlog none \
  closefrom 3 \
  softlimit -o 4 -f 0 -d $((4 * 1024 * 1024)) \
  sredird -t 900 5 /dev/console@getpid
~~~

# EXAMPLES

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

    RESTRICT_PROCESS=rlimit ./musl-make clean all test

    ## linux seccomp sandbox: requires kernel headers

    # clone the kernel headers somewhere
    cd /path/to/dir
    git clone https://github.com/sabotage-linux/kernel-headers.git

    # then compile
    MUSL_INCLUDE=/path/to/dir ./musl-make clean all test

# ALTERNATIVES

# COPYRIGHT

Copyright (C) 1999 - 2003 InfoTecna s.r.l.
Copyright (C) 2001, 2002 Trustees of Columbia University in the City of New York
Copyright (C) 2020-2021 Michael Santos <michael.santos@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
