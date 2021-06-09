/*
    sredird: RFC 2217 compliant serial port redirector
    Version 2.2.1, 20 February 2004
    Copyright (C) 1999 - 2003 InfoTecna s.r.l.
    Copyright (C) 2001, 2002 Trustees of Columbia University
    in the City of New York
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
*/
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "restrict_process.h"

/* Version id */
#define VersionId "2.2.1"
#define SRedirdVersionId "Version " VersionId ", 20 February 2004"

/* Maximum length of temporary strings */
#define TmpStrLen 255

/* Buffer size */
#define BufferSize 2048

/* Base Telnet protocol constants (STD 8) */
#define TNSE 240
#define TNNOP 241
#define TNSB 250
#define TNWILL 251
#define TNWONT 252
#define TNDO 253
#define TNDONT 254
#define TNIAC 255

/* Base Telnet protocol options constants (STD 27, STD 28, STD 29) */
#define TN_TRANSMIT_BINARY 0
#define TN_ECHO 1
#define TN_SUPPRESS_GO_AHEAD 3

/* Base Telnet Com Port Control (CPC) protocol constants (RFC 2217) */
#define TNCOM_PORT_OPTION 44

/* CPC Client to Access Server constants */
#define TNCAS_SIGNATURE 0
#define TNCAS_SET_BAUDRATE 1
#define TNCAS_SET_DATASIZE 2
#define TNCAS_SET_PARITY 3
#define TNCAS_SET_STOPSIZE 4
#define TNCAS_SET_CONTROL 5
#define TNCAS_NOTIFY_LINESTATE 6
#define TNCAS_NOTIFY_MODEMSTATE 7
#define TNCAS_FLOWCONTROL_SUSPEND 8
#define TNCAS_FLOWCONTROL_RESUME 9
#define TNCAS_SET_LINESTATE_MASK 10
#define TNCAS_SET_MODEMSTATE_MASK 11
#define TNCAS_PURGE_DATA 12

/* CPC Access Server to Client constants */
#define TNASC_SIGNATURE 100
#define TNASC_SET_BAUDRATE 101
#define TNASC_SET_DATASIZE 102
#define TNASC_SET_PARITY 103
#define TNASC_SET_STOPSIZE 104
#define TNASC_SET_CONTROL 105
#define TNASC_NOTIFY_LINESTATE 106
#define TNASC_NOTIFY_MODEMSTATE 107
#define TNASC_FLOWCONTROL_SUSPEND 108
#define TNASC_FLOWCONTROL_RESUME 109
#define TNASC_SET_LINESTATE_MASK 110
#define TNASC_SET_MODEMSTATE_MASK 111
#define TNASC_PURGE_DATA 112

/* Modem state effective change mask */
#define ModemStateECMask 255

#define LineStateECMask 255

/* Default modem state polling in milliseconds (100 msec should be enough) */
#define ModemStatePolling 100

#define COUNT(_array) (sizeof(_array) / sizeof(_array[0]))

#define DEVICE_FILENO 2

/* Standard boolean definition */
typedef enum { False, True } Boolean;

/* Cisco IOS bug compatibility */
static Boolean CiscoIOSCompatible = False;

/* Buffer structure */
typedef struct {
  unsigned char Buffer[BufferSize];
  unsigned int RdPos;
  unsigned int WrPos;
} BufferType;

/* Complete device file pathname */
static const char *DeviceName;

/* Device file descriptor */
static int DeviceFd = -1;

/* Com Port Control enabled flag */
static Boolean TCPCEnabled = False;

/* True after retrieving the initial settings from the serial port */
static Boolean InitPortRetrieved = False;

/* Initial serial port settings */
static struct termios InitialPortSettings;

/* Maximum log level to log in the system log */
static int MaxLogLevel = LOG_DEBUG + 1;

/* Status enumeration for IAC escaping and interpretation */
typedef enum { IACNormal, IACReceived, IACComReceiving } IACState;

/* Effective status for IAC escaping and interpretation */
static IACState IACEscape = IACNormal;

/* Same as above during signature reception */
static IACState IACSigEscape;

/* Current IAC command begin received */
static unsigned char IACCommand[TmpStrLen];

/* Position of insertion into IACCommand[] */
static size_t IACPos;

/* Modem state mask set by the client */
static unsigned char ModemStateMask = 255;

/* Line state mask set by the client */
static unsigned char LineStateMask = 0;

#ifdef COMMENT
/* Current status of the line control lines */
static unsigned char LineState = 0;
#endif

/* Current status of the modem control lines */
static unsigned char ModemState = 0;

/* Break state flag */
static Boolean BreakSignaled = False;

/* Input flow control flag */
static Boolean InputFlow = True;

/* Telnet State Machine */
static struct _tnstate {
  unsigned int sent_will : 1;
  unsigned int sent_do : 1;
  unsigned int sent_wont : 1;
  unsigned int sent_dont : 1;
  unsigned int is_will : 1;
  unsigned int is_do : 1;
} tnstate[256];

/* Function prototypes */

/* initialize Telnet State Machine */
void InitTelnetStateMachine(void);

/* Initialize a buffer for operation */
void InitBuffer(BufferType *B);

/* Check if the buffer is empty */
static Boolean IsBufferEmpty(BufferType *B);

/* Check if the buffer is full */
static Boolean IsBufferFull(BufferType *B);

/* Add a byte to a buffer */
void AddToBuffer(BufferType *B, unsigned char C);

/* Push a byte to a buffer */
void PushToBuffer(BufferType *B, unsigned char C);

/* Get a byte from a buffer */
unsigned char GetFromBuffer(BufferType *B);

/* Generic log function with log level control. Uses the same log levels
of the syslog(3) system call */
void LogMsg(int LogLevel, const char *const fmt, ...);

/* Function executed when the program exits */
static noreturn void ExitFunction(void);

/* Function called on many signals */
static noreturn void SignalFunction(int unused);

/* Function called on break signal */
static noreturn void BreakFunction(int unused);

/* Retrieves the port speed from PortFd */
unsigned long int GetPortSpeed(int PortFd);

/* Retrieves the data size from PortFd */
unsigned char GetPortDataSize(int PortFd);

/* Retrieves the parity settings from PortFd */
unsigned char GetPortParity(int PortFd);

/* Retrieves the stop bits size from PortFd */
unsigned char GetPortStopSize(int PortFd);

/* Retrieves the flow control status, including DTR and RTS status,
from PortFd */
unsigned char GetPortFlowControl(int PortFd, unsigned char Which);

/* Return the status of the modem control lines (DCD, CTS, DSR, RNG) */
unsigned char GetModemState(int PortFd, unsigned char PMState);

/* Set the serial port data size */
void SetPortDataSize(int PortFd, unsigned char DataSize);

/* Set the serial port parity */
void SetPortParity(int PortFd, unsigned char Parity);

/* Set the serial port stop bits size */
void SetPortStopSize(int PortFd, unsigned char StopSize);

/* Set the port flow control and DTR and RTS status */
void SetPortFlowControl(int PortFd, unsigned char How);

/* Set the serial port speed */
void SetPortSpeed(int PortFd, unsigned long BaudRate);

/* Send the signature Sig to the client */
void SendSignature(BufferType *B, char *Sig);

/* Write a char to SockFd performing IAC escaping */
void EscWriteChar(BufferType *B, unsigned char C);

/* Redirect char C to PortFd checking for IAC escape sequences */
void EscRedirectChar(BufferType *SockB, BufferType *DevB, int PortFd,
                     unsigned char C);

/* Send the specific telnet option to SockFd using Command as command */
void SendTelnetOption(BufferType *B, unsigned char Command, char Option);

/* Send a string to SockFd performing IAC escaping */
void SendStr(BufferType *B, char *Str);

/* Send the baud rate BR to SockFd */
void SendBaudRate(BufferType *B, unsigned long int BR);

/* Send the flow control command Command */
void SendCPCFlowCommand(BufferType *B, unsigned char Command);

/* Send the CPC command Command using Parm as parameter */
void SendCPCByteCommand(BufferType *B, unsigned char Command,
                        unsigned char Parm);

/* Handling of COM Port Control specific commands */
void HandleCPCCommand(BufferType *B, int PortFd, unsigned char *Command,
                      size_t CSize);

/* Common telnet IAC commands handling */
void HandleIACCommand(BufferType *B, int PortFd, unsigned char *Command,
                      size_t CSize);

/* Write a buffer to SockFd with IAC escaping */
void EscWriteBuffer(BufferType *B, unsigned char *Buffer, unsigned int BSize);

/* Usage */
void Usage(void);

static const struct option long_options[] = {
    {"timeout", required_argument, NULL, 't'},
    {"cisco-compatibility", no_argument, NULL, 'i'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}};

/* initialize Telnet State Machine */
void InitTelnetStateMachine(void) {
  int i;
  for (i = 0; i < 256; i++) {
    tnstate[i].sent_do = 0;
    tnstate[i].sent_will = 0;
    tnstate[i].sent_wont = 0;
    tnstate[i].sent_dont = 0;
    tnstate[i].is_do = 0;
    tnstate[i].is_will = 0;
  }
}

/* Initialize a buffer for operation */
void InitBuffer(BufferType *B) {
  /* Set the initial buffer positions */
  B->RdPos = 0;
  B->WrPos = 0;
}

/* Check if the buffer is empty */
Boolean IsBufferEmpty(BufferType *B) { return ((Boolean)B->RdPos == B->WrPos); }

/* Check if the buffer is full */
Boolean IsBufferFull(BufferType *B) {
  /* We consider the buffer to be filled when there are 100 bytes left
    This is so even a full buffer can safely have escaped characters
    added to it.
  */
  return ((Boolean)B->WrPos == (B->RdPos + BufferSize - 101) % BufferSize);
}

/* Add a byte to a buffer */
void AddToBuffer(BufferType *B, unsigned char C) {
  B->Buffer[B->WrPos] = C;
  B->WrPos = (B->WrPos + 1) % BufferSize;
}

void PushToBuffer(BufferType *B, unsigned char C) {
  if (B->RdPos > 0)
    B->RdPos--;
  else
    B->RdPos = BufferSize - 1;

  B->Buffer[B->RdPos] = C;
}

/* Get a byte from a buffer */
unsigned char GetFromBuffer(BufferType *B) {
  unsigned char C = B->Buffer[B->RdPos];
  B->RdPos = (B->RdPos + 1) % BufferSize;
  return C;
}

/* Generic log function with log level control. Uses the same log levels
of the syslog(3) system call */
void LogMsg(int LogLevel, const char *const fmt, ...) {
  va_list ap;
  if (LogLevel <= MaxLogLevel) {
    (void)fprintf(stderr, "%s: ", DeviceName);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");
  }
}

/* Function executed when the program exits */
static noreturn void ExitFunction(void) {
  const char *message = "SRedird stopped.\n";

  /* Restores initial port settings */
  if (DeviceFd > -1) {
    if (InitPortRetrieved == True)
      tcsetattr(DeviceFd, TCSANOW, &InitialPortSettings);
  }

  /* Program termination notification */
  if (MaxLogLevel >= LOG_NOTICE) {
    /* warning: ignoring return value of ‘write’, declared with attribute
     * warn_unused_result [-Wunused-result] */
    if (write(STDERR_FILENO, message, strlen(message)) == -1) {
    }
  }

  _exit(0);
}

/* Function called on many signals */
static noreturn void SignalFunction(int unused) {
  (void)unused;

  /* Same as the exit function */
  ExitFunction();
}

/* Function called on break signal */
/* Unimplemented yet */
static noreturn void BreakFunction(int unused) {
#ifndef COMMENT
  (void)unused;

  /* Same as the exit function */
  ExitFunction();
#else  /* COMMENT */

  unsigned char LineState;

  if (BreakSignaled == True) {
    BreakSignaled = False;
    LineState = 0;
  } else {
    BreakSignaled = True;
    LineState = 16;
  }

  /* Notify client of break change */
  if ((LineStateMask & (unsigned char)16) != 0) {
    LogMsg(LOG_DEBUG, "Notifying break change.");
    SendCPCByteCommand(&ToNetBuf, TNASC_NOTIFY_LINESTATE, LineState);
  }
#endif /* COMMENT */
}

/* Retrieves the port speed from PortFd */
unsigned long int GetPortSpeed(int PortFd) {
  struct termios PortSettings;
  speed_t Speed;

  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");
  Speed = cfgetospeed(&PortSettings);

  switch (Speed) {
  case B50:
    return 50UL;
  case B75:
    return 75UL;
  case B110:
    return 110UL;
  case B134:
    return 134UL;
  case B150:
    return 150UL;
  case B200:
    return 200UL;
  case B300:
    return 300UL;
  case B600:
    return 600UL;
  case B1200:
    return 1200UL;
  case B1800:
    return 1800UL;
  case B2400:
    return 2400UL;
  case B4800:
    return 4800UL;
  case B9600:
    return 9600UL;
  case B19200:
    return 19200UL;
  case B38400:
    return 38400UL;
  case B57600:
    return 57600UL;
  case B115200:
    return 115200UL;
  case B230400:
    return 230400UL;
#ifdef B460800
  case B460800:
    return 460800UL;
#endif
  default:
    return 0UL;
  }
}

/* Retrieves the data size from PortFd */
unsigned char GetPortDataSize(int PortFd) {
  struct termios PortSettings;
  tcflag_t DataSize;

  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgettattr");
  DataSize = PortSettings.c_cflag & CSIZE;

  switch (DataSize) {
  case CS5:
    return 5;
  case CS6:
    return 6;
  case CS7:
    return 7;
  case CS8:
    return 8;
  default:
    return 0;
  }
}

/* Retrieves the parity settings from PortFd */
unsigned char GetPortParity(int PortFd) {
  struct termios PortSettings;

  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");

  if ((PortSettings.c_cflag & PARENB) == 0)
    return 1;

  if ((PortSettings.c_cflag & PARENB) != 0 &&
      (PortSettings.c_cflag & PARODD) != 0)
    return 2;

  return 3;
}

/* Retrieves the stop bits size from PortFd */
unsigned char GetPortStopSize(int PortFd) {
  struct termios PortSettings;

  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");

  if ((PortSettings.c_cflag & CSTOPB) == 0)
    return 1;

  return 2;
}

/* Retrieves the flow control status, including DTR and RTS status,
from PortFd */
unsigned char GetPortFlowControl(int PortFd, unsigned char Which) {
  struct termios PortSettings;
  int MLines;

  /* Gets the basic informations from the port */
  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");
  if (ioctl(PortFd, TIOCMGET, &MLines) < 0)
    err(EXIT_FAILURE, "ioctl(TIOCMGET)");

  /* Check which kind of information is requested */
  switch (Which) {
  /* Com Port Flow Control Setting (outbound/both) */
  case 0:
    if (PortSettings.c_iflag & IXON)
      return 2;
    if (PortSettings.c_cflag & CRTSCTS)
      return 3;
    return 1;

  /* BREAK State  */
  case 4:
    if (BreakSignaled == True)
      return 5;
    return 6;

  /* DTR Signal State */
  case 7:
    if (MLines & TIOCM_DTR)
      return 8;
    return 9;

  /* RTS Signal State */
  case 10:
    if (MLines & TIOCM_RTS)
      return 11;
    return 12;

  /* Com Port Flow Control Setting (inbound) */
  case 13:
    if (PortSettings.c_iflag & IXOFF)
      return 15;
    if (PortSettings.c_cflag & CRTSCTS)
      return 16;
    return 14;

  default:
    if (PortSettings.c_iflag & IXON)
      return 2;
    if (PortSettings.c_cflag & CRTSCTS)
      return 3;
    return 1;
  }
}

/* Return the status of the modem control lines (DCD, CTS, DSR, RNG) */
unsigned char GetModemState(int PortFd, unsigned char PMState) {
  int MLines;
  unsigned char MState = 0;

  if (ioctl(PortFd, TIOCMGET, &MLines) < 0)
    err(EXIT_FAILURE, "ioctl(TIOCMGET)");

  if ((MLines & TIOCM_CAR) != 0)
    MState += 128;
  if ((MLines & TIOCM_RNG) != 0)
    MState += 64;
  if ((MLines & TIOCM_DSR) != 0)
    MState += 32;
  if ((MLines & TIOCM_CTS) != 0)
    MState += 16;
  if ((MState & 128) != (PMState & 128))
    MState += 8;
  if ((MState & 64) != (PMState & 64))
    MState += 4;
  if ((MState & 32) != (PMState & 32))
    MState += 2;
  if ((MState & 16) != (PMState & 16))
    MState += 1;

  return MState;
}

/* Set the serial port data size */
void SetPortDataSize(int PortFd, unsigned char DataSize) {
  struct termios PortSettings;
  tcflag_t PDataSize;

  switch (DataSize) {
  case 5:
    PDataSize = CS5;
    break;
  case 6:
    PDataSize = CS6;
    break;
  case 7:
    PDataSize = CS7;
    break;
  case 8:
    PDataSize = CS8;
    break;
  default:
    PDataSize = CS8;
    break;
  }

  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");
  PortSettings.c_cflag &= ~CSIZE;
  PortSettings.c_cflag |= PDataSize & CSIZE;
  if (tcsetattr(PortFd, TCSADRAIN, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcsetattr");
}

/* Set the serial port parity */
void SetPortParity(int PortFd, unsigned char Parity) {
  struct termios PortSettings;

  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");

  switch (Parity) {
  case 1:
    PortSettings.c_cflag = PortSettings.c_cflag & ~PARENB;
    break;
  case 2:
    PortSettings.c_cflag = PortSettings.c_cflag | PARENB | PARODD;
    break;
  case 3:
    PortSettings.c_cflag = (PortSettings.c_cflag | PARENB) & ~PARODD;
    break;
  /* There's no support for MARK and SPACE parity so sets no parity */
  default:
    LogMsg(LOG_WARNING, "Requested unsupported parity, set to no parity.");
    PortSettings.c_cflag = PortSettings.c_cflag & ~PARENB;
    break;
  }

  if (tcsetattr(PortFd, TCSADRAIN, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcsetattr");
}

/* Set the serial port stop bits size */
void SetPortStopSize(int PortFd, unsigned char StopSize) {
  struct termios PortSettings;

  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");

  switch (StopSize) {
  case 1:
    PortSettings.c_cflag = PortSettings.c_cflag & ~CSTOPB;
    break;
  case 2:
    PortSettings.c_cflag = PortSettings.c_cflag | CSTOPB;
    break;
  case 3:
    PortSettings.c_cflag = PortSettings.c_cflag & ~CSTOPB;
    LogMsg(LOG_WARNING,
           "Requested unsupported 1.5 bits stop size, set to 1 bit stop size.");
    break;
  default:
    PortSettings.c_cflag = PortSettings.c_cflag & ~CSTOPB;
    break;
  }

  if (tcsetattr(PortFd, TCSADRAIN, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcsetattr");
}

/* Set the port flow control and DTR and RTS status */
void SetPortFlowControl(int PortFd, unsigned char How) {
  struct termios PortSettings;
  int MLines;

  /* Gets the base status from the port */
  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");
  if (ioctl(PortFd, TIOCMGET, &MLines) < 0)
    err(EXIT_FAILURE, "ioctl(TIOCMGET)");

  /* Check which settings to change */
  switch (How) {
  /* No Flow Control (outbound/both) */
  case 1:
    PortSettings.c_iflag = PortSettings.c_iflag & ~IXON;
    PortSettings.c_iflag = PortSettings.c_iflag & ~IXOFF;
    PortSettings.c_cflag = PortSettings.c_cflag & ~CRTSCTS;
    break;
  /* XON/XOFF Flow Control (outbound/both) */
  case 2:
    PortSettings.c_iflag = PortSettings.c_iflag | IXON;
    PortSettings.c_iflag = PortSettings.c_iflag | IXOFF;
    PortSettings.c_cflag = PortSettings.c_cflag & ~CRTSCTS;
    break;
  /* HARDWARE Flow Control (outbound/both) */
  case 3:
    PortSettings.c_iflag = PortSettings.c_iflag & ~IXON;
    PortSettings.c_iflag = PortSettings.c_iflag & ~IXOFF;
    PortSettings.c_cflag = PortSettings.c_cflag | CRTSCTS;
    break;
  /* BREAK State ON */
  case 5:
    if (tcsendbreak(PortFd, 1) < 0)
      err(EXIT_FAILURE, "tcsendbreak");
    BreakSignaled = True;
    break;
  /* BREAK State OFF */
  case 6:
    /* Should not send another break */
    /* tcsendbreak(PortFd,0); */
    BreakSignaled = False;
    break;
  /* DTR Signal State ON */
  case 8:
    MLines = MLines | TIOCM_DTR;
    break;
  /* DTR Signal State OFF */
  case 9:
    MLines = MLines & ~TIOCM_DTR;
    break;
  /* RTS Signal State ON */
  case 11:
    MLines = MLines | TIOCM_RTS;
    break;
  /* RTS Signal State OFF */
  case 12:
    MLines = MLines & ~TIOCM_RTS;
    break;

  /* INBOUND FLOW CONTROL is ignored */
  /* No Flow Control (inbound) */
  case 14:
  /* XON/XOFF Flow Control (inbound) */
  case 15:
  /* HARDWARE Flow Control (inbound) */
  case 16:
    LogMsg(LOG_WARNING, "Inbound flow control ignored.");
    break;
  default:
    LogMsg(LOG_WARNING, "Requested unsupported flow control.");
    break;
  }

  if (tcsetattr(PortFd, TCSADRAIN, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcsetattr");
  if (ioctl(PortFd, TIOCMSET, &MLines) < 0)
    err(EXIT_FAILURE, "ioctl(TIOCMSET)");
}

/* Set the serial port speed */
void SetPortSpeed(int PortFd, unsigned long BaudRate) {
  struct termios PortSettings;
  speed_t Speed;

  switch (BaudRate) {
  case 50UL:
    Speed = B50;
    break;
  case 75UL:
    Speed = B75;
    break;
  case 110UL:
    Speed = B110;
    break;
  case 134UL:
    Speed = B134;
    break;
  case 150UL:
    Speed = B150;
    break;
  case 200UL:
    Speed = B200;
    break;
  case 300UL:
    Speed = B300;
    break;
  case 600UL:
    Speed = B600;
    break;
  case 1200UL:
    Speed = B1200;
    break;
  case 1800UL:
    Speed = B1800;
    break;
  case 2400UL:
    Speed = B2400;
    break;
  case 4800UL:
    Speed = B4800;
    break;
  case 9600UL:
    Speed = B9600;
    break;
  case 19200UL:
    Speed = B19200;
    break;
  case 38400UL:
    Speed = B38400;
    break;
  case 57600UL:
    Speed = B57600;
    break;
  case 115200UL:
    Speed = B115200;
    break;
  case 230400UL:
    Speed = B230400;
    break;
#ifdef B460800
  case 460800UL:
    Speed = B460800;
    break;
#endif
  default:
    LogMsg(LOG_WARNING, "Unknown baud rate requested, setting to 9600.");
    Speed = B9600;
    break;
  }

  if (tcgetattr(PortFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");
  if (cfsetospeed(&PortSettings, Speed) < 0)
    err(EXIT_FAILURE, "cfsetospeed");
  if (cfsetispeed(&PortSettings, Speed) < 0)
    err(EXIT_FAILURE, "cfsetispeed");
  if (tcsetattr(PortFd, TCSADRAIN, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcsetattr");
}

/* Send the signature Sig to the client */
void SendSignature(BufferType *B, char *Sig) {
  AddToBuffer(B, TNIAC);
  AddToBuffer(B, TNSB);
  AddToBuffer(B, TNCOM_PORT_OPTION);
  AddToBuffer(B, TNASC_SIGNATURE);
  SendStr(B, Sig);
  AddToBuffer(B, TNIAC);
  AddToBuffer(B, TNSE);
}

/* Write a char to socket performing IAC escaping */
void EscWriteChar(BufferType *B, unsigned char C) {
  /* Last received byte */
  static unsigned char Last = 0;

  if (C == TNIAC)
    AddToBuffer(B, C);
  else if (C != 0x0A && !tnstate[TN_TRANSMIT_BINARY].is_will && Last == 0x0D)
    AddToBuffer(B, 0x00);
  AddToBuffer(B, C);

  /* Set last received byte */
  Last = C;
}

/* Redirect char C to Device checking for IAC escape sequences */
void EscRedirectChar(BufferType *SockB, BufferType *DevB, int PortFd,
                     unsigned char C) {
  /* Last received byte */
  static unsigned char Last = 0;

  /* Check the IAC escape status */
  switch (IACEscape) {
  /* Normal status */
  case IACNormal:
    if (C == TNIAC)
      IACEscape = IACReceived;
    else if (!tnstate[TN_TRANSMIT_BINARY].is_do && C == 0x00 && Last == 0x0D)
      /* Swallow the NUL after a CR if not receiving BINARY */
      break;
    else
      AddToBuffer(DevB, C);
    break;

  /* IAC previously received */
  case IACReceived:
    if (C == TNIAC) {
      AddToBuffer(DevB, C);
      IACEscape = IACNormal;
    } else {
      IACCommand[0] = TNIAC;
      IACCommand[1] = C;
      IACPos = 2;
      IACEscape = IACComReceiving;
      IACSigEscape = IACNormal;
    }
    break;

  /* IAC Command reception */
  case IACComReceiving:
    /* Telnet suboption, could be only CPC */
    if (IACCommand[1] == TNSB) {
      /* Get the suboption signature */
      if (IACPos < 4) {
        IACCommand[IACPos] = C;
        IACPos++;
      } else {
        /* Check which suboption we are dealing with */
        switch (IACCommand[3]) {
        /* Signature, which needs further escaping */
        case TNCAS_SIGNATURE:
          switch (IACSigEscape) {
          case IACNormal:
            if (C == TNIAC)
              IACSigEscape = IACReceived;
            else if (IACPos < TmpStrLen) {
              IACCommand[IACPos] = C;
              IACPos++;
            }
            break;

          case IACComReceiving:
            IACSigEscape = IACNormal;
            break;

          case IACReceived:
            if (C == TNIAC) {
              if (IACPos < TmpStrLen) {
                IACCommand[IACPos] = C;
                IACPos++;
              }
              IACSigEscape = IACNormal;
            } else {
              if (IACPos < TmpStrLen) {
                IACCommand[IACPos] = TNIAC;
                IACPos++;
              }

              if (IACPos < TmpStrLen) {
                IACCommand[IACPos] = C;
                IACPos++;
              }

              HandleIACCommand(SockB, PortFd, IACCommand, IACPos);
              IACEscape = IACNormal;
            }
            break;
          }
          break;

        /* Set baudrate */
        case TNCAS_SET_BAUDRATE:
          IACCommand[IACPos] = C;
          IACPos++;

          if (IACPos == 10) {
            HandleIACCommand(SockB, PortFd, IACCommand, IACPos);
            IACEscape = IACNormal;
          }
          break;

        /* Flow control command */
        case TNCAS_FLOWCONTROL_SUSPEND:
        case TNCAS_FLOWCONTROL_RESUME:
          IACCommand[IACPos] = C;
          IACPos++;

          if (IACPos == 6) {
            HandleIACCommand(SockB, PortFd, IACCommand, IACPos);
            IACEscape = IACNormal;
          }
          break;

        /* Normal CPC command with single byte parameter */
        default:
          IACCommand[IACPos] = C;
          IACPos++;

          if (IACPos == 7) {
            HandleIACCommand(SockB, PortFd, IACCommand, IACPos);
            IACEscape = IACNormal;
          }
          break;
        }
      }
    } else {
      /* Normal 3 byte IAC option */
      IACCommand[IACPos] = C;
      IACPos++;

      if (IACPos == 3) {
        HandleIACCommand(SockB, PortFd, IACCommand, IACPos);
        IACEscape = IACNormal;
      }
    }
    break;
  }

  /* Set last received byte */
  Last = C;
}

/* Send the specific telnet option to SockFd using Command as command */
void SendTelnetOption(BufferType *B, unsigned char Command, char Option) {
  unsigned char IAC = TNIAC;

  AddToBuffer(B, IAC);
  AddToBuffer(B, Command);
  AddToBuffer(B, Option);
}

/* Send a string to SockFd performing IAC escaping */
void SendStr(BufferType *B, char *Str) {
  size_t I;
  size_t L;

  L = strlen(Str);

  for (I = 0; I < L; I++)
    EscWriteChar(B, (unsigned char)Str[I]);
}

/* Send the baud rate BR to Buffer */
void SendBaudRate(BufferType *B, unsigned long int BR) {
  unsigned char *p;
  unsigned long int NBR;
  int i;

  NBR = htonl(BR);

  AddToBuffer(B, TNIAC);
  AddToBuffer(B, TNSB);
  AddToBuffer(B, TNCOM_PORT_OPTION);
  AddToBuffer(B, TNASC_SET_BAUDRATE);
  p = (unsigned char *)&NBR;
  for (i = 0; i < (int)sizeof(NBR); i++)
    EscWriteChar(B, p[i]);
  AddToBuffer(B, TNIAC);
  AddToBuffer(B, TNSE);
}

/* Send the flow control command Command */
void SendCPCFlowCommand(BufferType *B, unsigned char Command) {
  AddToBuffer(B, TNIAC);
  AddToBuffer(B, TNSB);
  AddToBuffer(B, TNCOM_PORT_OPTION);
  AddToBuffer(B, Command);
  AddToBuffer(B, TNIAC);
  AddToBuffer(B, TNSE);

  if (Command == TNASC_FLOWCONTROL_SUSPEND)
    LogMsg(LOG_DEBUG, "Sent flow control suspend command.");
  else
    LogMsg(LOG_DEBUG, "Sent flow control resume command.");
}

/* Send the CPC command Command using Parm as parameter */
void SendCPCByteCommand(BufferType *B, unsigned char Command,
                        unsigned char Parm) {
  AddToBuffer(B, TNIAC);
  AddToBuffer(B, TNSB);
  AddToBuffer(B, TNCOM_PORT_OPTION);
  AddToBuffer(B, Command);
  EscWriteChar(B, Parm);
  AddToBuffer(B, TNIAC);
  AddToBuffer(B, TNSE);
}

/* Handling of COM Port Control specific commands */
void HandleCPCCommand(BufferType *SockB, int PortFd, unsigned char *Command,
                      size_t CSize) {
  char SigStr[TmpStrLen] = {0};
  unsigned long int BaudRate;
  unsigned char DataSize;
  unsigned char Parity;
  unsigned char StopSize;
  unsigned char FlowControl;

  /* Check which command has been requested */
  switch (Command[3]) {
  /* Signature */
  case TNCAS_SIGNATURE:
    if (CSize == 6) {
      /* Void signature, client is asking for our signature */
      (void)snprintf(SigStr, sizeof(SigStr) - 1, "SRedird %s %s", VersionId,
                     DeviceName);
      SendSignature(SockB, SigStr);
      LogMsg(LOG_INFO, "Sent signature: %s", SigStr);
    } else if (CSize > 6 && CSize < (sizeof(SigStr) - 1)) {
      /* Received client signature */
      strncpy(SigStr, (char *)&Command[4], CSize - 6);
      LogMsg(LOG_INFO, "Received client signature: %s", SigStr);
    }
    break;

  /* Set serial baud rate */
  case TNCAS_SET_BAUDRATE:
    /* Retrieve the baud rate which is in network order */
    BaudRate = ntohl(*((unsigned long int *)&Command[4]));

    if (BaudRate == 0)
      /* Client is asking for current baud rate */
      LogMsg(LOG_DEBUG, "Baud rate notification received.");
    else {
      /* Change the baud rate */
      LogMsg(LOG_DEBUG, "Port baud rate change to %lu requested.", BaudRate);
      SetPortSpeed(PortFd, BaudRate);
    }

    /* Send confirmation */
    BaudRate = GetPortSpeed(PortFd);
    SendBaudRate(SockB, BaudRate);
    LogMsg(LOG_DEBUG, "Port baud rate: %lu", BaudRate);
    break;

  /* Set serial data size */
  case TNCAS_SET_DATASIZE:
    if (Command[4] == 0)
      /* Client is asking for current data size */
      LogMsg(LOG_DEBUG, "Data size notification requested.");
    else {
      /* Set the data size */
      LogMsg(LOG_DEBUG, "Port data size change to %u requested.",
             (unsigned int)Command[4]);
      SetPortDataSize(PortFd, Command[4]);
    }

    /* Send confirmation */
    DataSize = GetPortDataSize(PortFd);
    SendCPCByteCommand(SockB, TNASC_SET_DATASIZE, DataSize);
    LogMsg(LOG_DEBUG, "Port data size: %u", (unsigned int)DataSize);
    break;

  /* Set the serial parity */
  case TNCAS_SET_PARITY:
    if (Command[4] == 0)
      /* Client is asking for current parity */
      LogMsg(LOG_DEBUG, "Parity notification requested.");
    else {
      /* Set the parity */
      LogMsg(LOG_DEBUG, "Port parity change to %u requested",
             (unsigned int)Command[4]);
      SetPortParity(PortFd, Command[4]);
    }

    /* Send confirmation */
    Parity = GetPortParity(PortFd);
    SendCPCByteCommand(SockB, TNASC_SET_PARITY, Parity);
    LogMsg(LOG_DEBUG, "Port parity: %u", (unsigned int)Parity);
    break;

  /* Set the serial stop size */
  case TNCAS_SET_STOPSIZE:
    if (Command[4] == 0)
      /* Client is asking for current stop size */
      LogMsg(LOG_DEBUG, "Stop size notification requested.");
    else {
      /* Set the stop size */
      LogMsg(LOG_DEBUG, "Port stop size change to %u requested.",
             (unsigned int)Command[4]);
      SetPortStopSize(PortFd, Command[4]);
    }

    /* Send confirmation */
    StopSize = GetPortStopSize(PortFd);
    SendCPCByteCommand(SockB, TNASC_SET_STOPSIZE, StopSize);
    LogMsg(LOG_DEBUG, "Port stop size: %u", (unsigned int)StopSize);
    break;

  /* Flow control and DTR/RTS handling */
  case TNCAS_SET_CONTROL:
    switch (Command[4]) {
    case 0:
    case 4:
    case 7:
    case 10:
    case 13:
      /* Client is asking for current flow control or DTR/RTS status */
      LogMsg(LOG_DEBUG, "Flow control notification requested.");
      FlowControl = GetPortFlowControl(PortFd, Command[4]);
      SendCPCByteCommand(SockB, TNASC_SET_CONTROL, FlowControl);
      LogMsg(LOG_DEBUG, "Port flow control: %u", (unsigned int)FlowControl);
      break;

    case 5:
      /* Break command */
      if (tcsendbreak(PortFd, 1) < 0)
        err(EXIT_FAILURE, "tcsendbreak");
      BreakSignaled = True;
      LogMsg(LOG_DEBUG, "Break Signal ON.");
      SendCPCByteCommand(SockB, TNASC_SET_CONTROL, Command[4]);
      break;

    case 6:
      BreakSignaled = False;
      LogMsg(LOG_DEBUG, "Break Signal OFF.");
      SendCPCByteCommand(SockB, TNASC_SET_CONTROL, Command[4]);
      break;

    default:
      /* Set the flow control */
      LogMsg(LOG_DEBUG, "Port flow control change to %u requested.",
             (unsigned int)Command[4]);
      SetPortFlowControl(PortFd, Command[4]);

      /* Flow control status confirmation */
      if (CiscoIOSCompatible && Command[4] >= 13 && Command[4] <= 16)
        /* INBOUND not supported separately.
          Following the behavior of Cisco ISO 11.3
        */
        FlowControl = 0;
      else
        /* Return the actual port flow control settings */
        FlowControl = GetPortFlowControl(PortFd, 0);

      SendCPCByteCommand(SockB, TNASC_SET_CONTROL, FlowControl);
      LogMsg(LOG_DEBUG, "Port flow control: %u", (unsigned int)FlowControl);
      break;
    }
    break;

  /* Set the line state mask */
  case TNCAS_SET_LINESTATE_MASK:
    LogMsg(LOG_DEBUG, "Line state set to %u", (unsigned int)Command[4]);

    /* Only break notification supported */
    LineStateMask = Command[4] & (unsigned char)16;
    SendCPCByteCommand(SockB, TNASC_SET_LINESTATE_MASK, LineStateMask);
    break;

  /* Set the modem state mask */
  case TNCAS_SET_MODEMSTATE_MASK:
    LogMsg(LOG_DEBUG, "Modem state mask set to %u", (unsigned int)Command[4]);
    ModemStateMask = Command[4];
    SendCPCByteCommand(SockB, TNASC_SET_MODEMSTATE_MASK, ModemStateMask);
    break;

  /* Port flush requested */
  case TNCAS_PURGE_DATA:
    LogMsg(LOG_DEBUG, "Port flush %u requested.", (unsigned int)Command[4]);
    switch (Command[4]) {
    /* Inbound flush */
    case 1:
      if (tcflush(PortFd, TCIFLUSH) < 0)
        err(EXIT_FAILURE, "tcflush");
      break;
    /* Outbound flush */
    case 2:
      if (tcflush(PortFd, TCOFLUSH) < 0)
        err(EXIT_FAILURE, "tcflush");
      break;
    /* Inbound/outbound flush */
    case 3:
      if (tcflush(PortFd, TCIOFLUSH) < 0)
        err(EXIT_FAILURE, "tcflush");
      break;
    }

    SendCPCByteCommand(SockB, TNASC_PURGE_DATA, Command[4]);
    break;

  /* Suspend output to the client */
  case TNCAS_FLOWCONTROL_SUSPEND:
    LogMsg(LOG_DEBUG, "Flow control suspend requested.");
    InputFlow = False;
    break;

  /* Resume output to the client */
  case TNCAS_FLOWCONTROL_RESUME:
    LogMsg(LOG_DEBUG, "Flow control resume requested.");
    InputFlow = True;
    break;

  /* Unknown request */
  default:
    LogMsg(LOG_DEBUG, "Unhandled request %u", (unsigned int)Command[3]);
    break;
  }
}

/* Common telnet IAC commands handling */
void HandleIACCommand(BufferType *SockB, int PortFd, unsigned char *Command,
                      size_t CSize) {
  /* Check which command */
  switch (Command[1]) {
  /* Suboptions */
  case TNSB:
    if (!(tnstate[Command[2]].is_will || tnstate[Command[2]].is_do))
      break;

    switch (Command[2]) {
    /* RFC 2217 COM Port Control Protocol option */
    case TNCOM_PORT_OPTION:
      HandleCPCCommand(SockB, PortFd, Command, CSize);
      break;

    default:
      LogMsg(LOG_DEBUG, "Unknown suboption received: %u",
             (unsigned int)Command[2]);
      break;
    }
    break;

  /* Requests for options */
  case TNWILL:
    switch (Command[2]) {
    /* COM Port Control Option */
    case TNCOM_PORT_OPTION:
      LogMsg(LOG_INFO, "Telnet COM Port Control Enabled (WILL).");
      TCPCEnabled = True;
      if (!tnstate[Command[2]].sent_do) {
        SendTelnetOption(SockB, TNDO, Command[2]);
      }
      tnstate[Command[2]].is_do = 1;
      break;

    /* Telnet Binary mode */
    case TN_TRANSMIT_BINARY:
      LogMsg(LOG_INFO, "Telnet Binary Transfer Enabled (WILL).");
      if (!tnstate[Command[2]].sent_do)
        SendTelnetOption(SockB, TNDO, Command[2]);
      tnstate[Command[2]].is_do = 1;
      break;

    /* Echo request not handled */
    case TN_ECHO:
      LogMsg(LOG_INFO, "Rejecting Telnet Echo Option (WILL).");
      if (!tnstate[Command[2]].sent_do)
        SendTelnetOption(SockB, TNDO, Command[2]);
      tnstate[Command[2]].is_do = 1;
      break;

    /* No go ahead needed */
    case TN_SUPPRESS_GO_AHEAD:
      LogMsg(LOG_INFO, "Suppressing Go Ahead characters (WILL).");
      if (!tnstate[Command[2]].sent_do)
        SendTelnetOption(SockB, TNDO, Command[2]);
      tnstate[Command[2]].is_do = 1;
      break;

    /* Reject everything else */
    default:
      LogMsg(LOG_DEBUG, "Rejecting option WILL: %u", (unsigned int)Command[2]);
      SendTelnetOption(SockB, TNDONT, Command[2]);
      tnstate[Command[2]].is_do = 0;
      break;
    }
    tnstate[Command[2]].sent_do = 0;
    tnstate[Command[2]].sent_dont = 0;
    break;

  /* Confirmations for options */
  case TNDO:
    switch (Command[2]) {
    /* COM Port Control Option */
    case TNCOM_PORT_OPTION:
      LogMsg(LOG_INFO, "Telnet COM Port Control Enabled (DO).");
      TCPCEnabled = True;
      if (!tnstate[Command[2]].sent_will)
        SendTelnetOption(SockB, TNWILL, Command[2]);
      tnstate[Command[2]].is_will = 1;
      break;

    /* Telnet Binary mode */
    case TN_TRANSMIT_BINARY:
      LogMsg(LOG_INFO, "Telnet Binary Transfer Enabled (DO).");
      if (!tnstate[Command[2]].sent_will)
        SendTelnetOption(SockB, TNWILL, Command[2]);
      tnstate[Command[2]].is_will = 1;
      break;

    /* Echo request handled.  The modem will echo for the user. */
    case TN_ECHO:
      LogMsg(LOG_INFO, "Rejecting Telnet Echo Option (DO).");
      if (!tnstate[Command[2]].sent_will)
        SendTelnetOption(SockB, TNWILL, Command[2]);
      tnstate[Command[2]].is_will = 1;
      break;

    /* No go ahead needed */
    case TN_SUPPRESS_GO_AHEAD:
      LogMsg(LOG_INFO, "Suppressing Go Ahead characters (DO).");
      if (!tnstate[Command[2]].sent_will)
        SendTelnetOption(SockB, TNWILL, Command[2]);
      tnstate[Command[2]].is_will = 1;
      break;

    /* Reject everything else */
    default:
      LogMsg(LOG_DEBUG, "Rejecting option DO: %u", (unsigned int)Command[2]);
      SendTelnetOption(SockB, TNWONT, Command[2]);
      tnstate[Command[2]].is_will = 0;
      break;
    }
    tnstate[Command[2]].sent_will = 0;
    tnstate[Command[2]].sent_wont = 0;
    break;

  /* Notifications of rejections for options */
  case TNDONT:
    LogMsg(LOG_DEBUG, "Received rejection for option: %u",
           (unsigned int)Command[2]);
    if (tnstate[Command[2]].is_will) {
      SendTelnetOption(SockB, TNWONT, Command[2]);
      tnstate[Command[2]].is_will = 0;
    }
    tnstate[Command[2]].sent_will = 0;
    tnstate[Command[2]].sent_wont = 0;
    break;

  case TNWONT:
    if (Command[2] == TNCOM_PORT_OPTION) {
      LogMsg(LOG_ERR, "Client doesn't support Telnet COM Port "
                      "Protocol Option (RFC 2217), trying to serve anyway.");
    } else {
      LogMsg(LOG_DEBUG, "Received rejection for option: %u",
             (unsigned int)Command[2]);
    }
    if (tnstate[Command[2]].is_do) {
      SendTelnetOption(SockB, TNDONT, Command[2]);
      tnstate[Command[2]].is_do = 0;
    }
    tnstate[Command[2]].sent_do = 0;
    tnstate[Command[2]].sent_dont = 0;
    break;
  }
}

/* Write a buffer to SockFd with IAC escaping */
void EscWriteBuffer(BufferType *B, unsigned char *Buffer, unsigned int BSize) {
  unsigned int I;

  if (BSize > 0)
    for (I = 0; I < BSize; I++) {
      if (Buffer[I] == TNIAC)
        AddToBuffer(B, TNIAC);
      AddToBuffer(B, Buffer[I]);
    }
}

void Usage(void) {
  /* Write little usage information */
  (void)fprintf(
      stderr,
      "sredird: RFC 2217 compliant serial port redirector\n"
      "%s (using %s mode process restriction)\n"
      "Usage: sredird [<option>] <loglevel> <device> [pollinginterval]\n"
      "-i, --cisco-compatibility  indicates Cisco IOS Bug compatibility\n"
      "-t, --timeout <seconds>    set inactivity timeout\n"
      "Poll interval is in milliseconds, default is 100, 0 means no polling\n",
      SRedirdVersionId, RESTRICT_PROCESS);
}

/* Main function */
int main(int argc, char *argv[]) {
  /* fd set */
  struct pollfd fds[3] = {0};

  /* Char read */
  unsigned char C;

  /* Actual port settings */
  struct termios PortSettings;

  /* Poll interval */
  int poll_timeout;

  /* Remote flow control flag */
  Boolean RemoteFlowOff = False;

  /* Buffer to Device from Network */
  BufferType ToDevBuf;

  /* Buffer to Network from Device */
  BufferType ToNetBuf;

  /* Socket setup flag */
  int SockParmEnable = 1;

  /* Generic socket parameter */
  int SockParm;

  /* Optional argument processing indexes */
  int ch;

  unsigned int idle_timeout = 0;

  struct sigaction act = {0};

  if (restrict_process_init() < 0) {
    return EXIT_FAILURE;
  }

  DeviceName = "nodev";

  while ((ch = getopt_long(argc, argv, "iht:", long_options, NULL)) != -1) {
    switch (ch) {
    case 'i':
      if (CiscoIOSCompatible) {
        Usage();
        return EXIT_FAILURE;
      }
      CiscoIOSCompatible = True;
      break;
    case 't':
      idle_timeout = atoi(optarg);
      break;
    case 'h':
    default:
      Usage();
      return EXIT_FAILURE;
    }
  }

  argc -= optind;
  argv += optind;

  /* Check the command line argument count */
  if (argc < 2) {
    Usage();
    return EXIT_FAILURE;
  }

  /* Sets the log level */
  MaxLogLevel = atoi(argv[0]);

  /* Gets device file name */
  DeviceName = argv[1];

  /* Retrieve the polling interval */
  poll_timeout = ModemStatePolling;
  if (argc > 2) {
    poll_timeout = atoi(argv[2]);
  }

  /* Logs sredird start */
  LogMsg(LOG_NOTICE, "SRedird started.");

  /* Logs sredird log level */
  LogMsg(LOG_INFO, "Log level: %i", MaxLogLevel);

  /* Logs the polling interval */
  LogMsg(LOG_INFO, "Polling interval (ms): %d", poll_timeout);

  /* Register exit and signal handler functions */
  if (atexit(ExitFunction) != 0)
    return EXIT_FAILURE;

  act.sa_handler = SignalFunction;
  (void)sigfillset(&act.sa_mask);

  if (sigaction(SIGHUP, &act, NULL) != 0)
    return EXIT_FAILURE;
  if (sigaction(SIGQUIT, &act, NULL) != 0)
    return EXIT_FAILURE;
  if (sigaction(SIGABRT, &act, NULL) != 0)
    return EXIT_FAILURE;
  if (sigaction(SIGPIPE, &act, NULL) != 0)
    return EXIT_FAILURE;
  if (sigaction(SIGTERM, &act, NULL) != 0)
    return EXIT_FAILURE;
  if (sigaction(SIGALRM, &act, NULL) != 0)
    return EXIT_FAILURE;

  /* Register the function to be called on break condition */
  act.sa_handler = BreakFunction;
  if (sigaction(SIGINT, &act, NULL) != 0)
    return EXIT_FAILURE;

  if (idle_timeout > 0)
    alarm(idle_timeout);

  /* Open the device */
  if ((DeviceFd = open(DeviceName, O_RDWR | O_NOCTTY | O_NDELAY, 0)) == -1) {
    /* Open failed */
    LogMsg(LOG_ERR, "Unable to open device %s. Exiting.", DeviceName);
    return EXIT_FAILURE;
  }

  /* Get the actual port settings */
  if (tcgetattr(DeviceFd, &InitialPortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");
  InitPortRetrieved = True;
  if (tcgetattr(DeviceFd, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcgetattr");

  /* Set the serial port to raw mode */
  cfmakeraw(&PortSettings);

  /* Enable HANGUP on close and disable modem control line handling */
  PortSettings.c_cflag = (PortSettings.c_cflag | HUPCL) | CLOCAL;

  /* Enable break handling */
  PortSettings.c_iflag = (PortSettings.c_iflag & ~IGNBRK) | BRKINT;

  /* Write the port settings to device */
  if (tcsetattr(DeviceFd, TCSANOW, &PortSettings) < 0)
    err(EXIT_FAILURE, "tcsetattr");

  /* Reset the device fd to blocking mode */
  if (fcntl(DeviceFd, F_SETFL, fcntl(DeviceFd, F_GETFL) & ~(O_NDELAY)) == -1)
    LogMsg(LOG_ERR, "Unable to reset device to non blocking mode, ignoring.");

  /* Initialize the input buffer */
  InitBuffer(&ToDevBuf);
  InitBuffer(&ToNetBuf);

  /* Setup sockets for low latency and automatic keepalive;
   * doesn't check if anything fails because failure doesn't prevent
   * correct functioning but only provides slightly worse behaviour
   */
  SockParm = IPTOS_LOWDELAY;
  setsockopt(STDIN_FILENO, SOL_SOCKET, SO_KEEPALIVE, &SockParmEnable,
             sizeof(SockParmEnable));
#ifdef SOL_IP
  setsockopt(STDIN_FILENO, SOL_IP, IP_TOS, &SockParm, sizeof(SockParm));
#endif
  setsockopt(STDIN_FILENO, SOL_SOCKET, SO_OOBINLINE, &SockParmEnable,
             sizeof(SockParmEnable));
  setsockopt(STDOUT_FILENO, SOL_SOCKET, SO_KEEPALIVE, &SockParmEnable,
             sizeof(SockParmEnable));
#ifdef SOL_IP
  setsockopt(STDOUT_FILENO, SOL_IP, IP_TOS, &SockParm, sizeof(SockParm));
#endif

  /* Make reads/writes unblocking */
  if (ioctl(STDOUT_FILENO, FIONBIO, &SockParmEnable) < 0)
    err(EXIT_FAILURE, "ioctl(FIONBIO)");
  if (ioctl(STDIN_FILENO, FIONBIO, &SockParmEnable) < 0)
    err(EXIT_FAILURE, "ioctl(FIONBIO)");
  if (ioctl(DeviceFd, FIONBIO, &SockParmEnable) < 0)
    err(EXIT_FAILURE, "ioctl(FIONBIO)");

  /* Send initial Telnet negotiations to the client */
  InitTelnetStateMachine();
  SendTelnetOption(&ToNetBuf, TNWILL, TN_TRANSMIT_BINARY);
  tnstate[TN_TRANSMIT_BINARY].sent_will = 1;
  SendTelnetOption(&ToNetBuf, TNDO, TN_TRANSMIT_BINARY);
  tnstate[TN_TRANSMIT_BINARY].sent_do = 1;
  SendTelnetOption(&ToNetBuf, TNWILL, TN_ECHO);
  tnstate[TN_ECHO].sent_will = 1;
  SendTelnetOption(&ToNetBuf, TNWILL, TN_SUPPRESS_GO_AHEAD);
  tnstate[TN_SUPPRESS_GO_AHEAD].sent_will = 1;
  SendTelnetOption(&ToNetBuf, TNDO, TN_SUPPRESS_GO_AHEAD);
  tnstate[TN_SUPPRESS_GO_AHEAD].sent_do = 1;
  SendTelnetOption(&ToNetBuf, TNDO, TNCOM_PORT_OPTION);
  tnstate[TNCOM_PORT_OPTION].sent_do = 1;

  /* Set up fd sets */
  /* Initially we have to read from all, but we only have data to send
   * to the network */
  fds[STDIN_FILENO].fd = STDIN_FILENO;
  fds[STDOUT_FILENO].fd = STDOUT_FILENO;
  fds[DEVICE_FILENO].fd = DeviceFd;

  fds[STDIN_FILENO].events = POLLIN;
  fds[STDOUT_FILENO].events = POLLOUT;
  fds[DEVICE_FILENO].events = POLLIN;

  if (restrict_process_stdio(DeviceFd) < 0) {
    return EXIT_FAILURE;
  }

  /* Main loop with fd's control */
  for (;;) {
    if (poll(fds, COUNT(fds), poll_timeout) < 0) {
      if (errno == EINTR)
        continue;
      err(EXIT_FAILURE, "poll");
    }

    /* Handle buffers in the following order
     *   Error
     *   Output
     *   Input
     * In other words, ensure we can write, make room, read more data
     */
    if (fds[DEVICE_FILENO].revents & POLLOUT) {
      Boolean b = True;

      /* Write to serial port */
      while (b && !IsBufferEmpty(&ToDevBuf)) {
        C = GetFromBuffer(&ToDevBuf);
        switch (write(DeviceFd, &C, 1)) {
        case 1:
          if (idle_timeout > 0)
            alarm(idle_timeout);
          break;
        case 0:
          LogMsg(LOG_INFO, "EOF");
          return EXIT_SUCCESS;
        case -1:
          if (errno != EAGAIN) {
            LogMsg(LOG_NOTICE, "Error writing to device.");
            return EXIT_SUCCESS;
          }
          PushToBuffer(&ToDevBuf, C);
          b = False;
          break;
        }
      }
    }

    if (fds[STDOUT_FILENO].revents & POLLOUT) {
      Boolean b = True;

      /* Write to network */
      while (b && !IsBufferEmpty(&ToNetBuf)) {
        C = GetFromBuffer(&ToNetBuf);
        switch (write(STDOUT_FILENO, &C, 1)) {
        case 1:
          if (idle_timeout > 0)
            alarm(idle_timeout);
          break;
        case 0:
          LogMsg(LOG_INFO, "EOF");
          return EXIT_SUCCESS;
        case -1:
          if (errno != EAGAIN) {
            LogMsg(LOG_NOTICE, "Error writing to network.");
            return EXIT_SUCCESS;
          }
          PushToBuffer(&ToNetBuf, C);
          b = False;
          break;
        }
      }
    }

    if (fds[DEVICE_FILENO].revents & (POLLIN | POLLERR | POLLNVAL)) {
      Boolean b = True;

      /* Read from serial port */
      while (b && !IsBufferFull(&ToNetBuf)) {
        switch (read(DeviceFd, &C, 1)) {
        case 1:
          EscWriteChar(&ToNetBuf, C);
          if (idle_timeout > 0)
            alarm(idle_timeout);
          break;
        case 0:
          LogMsg(LOG_INFO, "EOF");
          return EXIT_SUCCESS;
        case -1:
          if (errno != EAGAIN) {
            LogMsg(LOG_NOTICE, "Error reading from device.");
            return EXIT_SUCCESS;
          }
          b = False;
          break;
        }
      }
    }

    if (fds[STDIN_FILENO].revents & (POLLIN | POLLERR | POLLNVAL)) {
      Boolean b = True;

      /* Read from network */
      while (b && !IsBufferFull(&ToDevBuf)) {
        switch (read(STDIN_FILENO, &C, 1)) {
        case 1:
          EscRedirectChar(&ToNetBuf, &ToDevBuf, DeviceFd, C);
          if (idle_timeout > 0)
            alarm(idle_timeout);
          break;
        case 0:
          LogMsg(LOG_INFO, "EOF");
          return EXIT_SUCCESS;
        case -1:
          if (errno != EAGAIN) {
            LogMsg(LOG_NOTICE, "Error reading from network.");
            return EXIT_SUCCESS;
          }
          b = False;
          break;
        }
      }
    }

    if ((fds[STDIN_FILENO].revents & POLLHUP) ||
        (fds[DEVICE_FILENO].revents & POLLHUP)) {
      return EXIT_SUCCESS;
    }

    /* Check if the buffer is not full and remote flow is off */
    if (RemoteFlowOff == True && IsBufferFull(&ToDevBuf) == False) {
      /* Send a flow control resume command */
      SendCPCFlowCommand(&ToNetBuf, TNASC_FLOWCONTROL_RESUME);
      RemoteFlowOff = False;
    }

    /* Check the port state and notify the client if it's changed */
    if (TCPCEnabled == True && InputFlow == True) {
      if ((GetModemState(DeviceFd, ModemState) & ModemStateMask &
           ModemStateECMask) !=
          (ModemState & ModemStateMask & ModemStateECMask)) {
        ModemState = GetModemState(DeviceFd, ModemState);
        SendCPCByteCommand(&ToNetBuf, TNASC_NOTIFY_MODEMSTATE,
                           (ModemState & ModemStateMask));
        LogMsg(LOG_DEBUG, "Sent modem state: %u",
               (unsigned int)(ModemState & ModemStateMask));
      }
#ifdef COMMENT
      /* GetLineState() not yet implemented */
      if ((GetLineState(DeviceFd, LineState) & LineStateMask &
           LineStateECMask) != (LineState & LineStateMask & LineStateECMask)) {
        LineState = GetLineState(DeviceFd, LineState);
        SendCPCByteCommand(&ToNetBuf, TNASC_NOTIFY_LINESTATE,
                           (LineState & LineStateMask));
        LogMsg(LOG_DEBUG, "Sent line state: %u",
               (unsigned int)(LineState & LineStateMask));
      }
#endif /* COMMENT */
    }

    fds[STDIN_FILENO].events = 0;
    fds[STDOUT_FILENO].events = 0;
    fds[DEVICE_FILENO].events = 0;

    /* Check if the buffer is not full */
    if (IsBufferFull(&ToDevBuf) == False) {
      fds[STDIN_FILENO].events |= POLLIN;
    } else if (RemoteFlowOff == False) {
      /* Send a flow control suspend command */
      SendCPCFlowCommand(&ToNetBuf, TNASC_FLOWCONTROL_SUSPEND);
      RemoteFlowOff = True;
    }

    /* If input flow has been disabled from the remote client
    don't read from the device */
    if (!IsBufferFull(&ToNetBuf) && InputFlow == True)
      fds[DEVICE_FILENO].events |= POLLIN;

    /* Check if there are characters available to write */
    if (!IsBufferEmpty(&ToDevBuf))
      fds[DEVICE_FILENO].events |= POLLOUT;
    if (!IsBufferEmpty(&ToNetBuf))
      fds[STDOUT_FILENO].events |= POLLOUT;
  }
}
