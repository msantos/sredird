/*
    sredird: RFC 2217 compliant serial port redirector
    Version 2.2.1, 20 February 2004
    Copyright (C) 1999 - 2003 InfoTecna s.r.l.
    Copyright (C) 2001, 2002 Trustees of Columbia University
    in the City of New York

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

    To contact the authors:

      Denis Sbragion
      InfoTecna
      Tel, Fax: +39 0362 805396
      URL: http://www.infotecna.it
      E-Mail: d.sbragion@infotecna.it

      Jeffrey Altman
      The Kermit Project
      Columbia University
      URL: http://www.kermit-project.org/
      E-mail: jaltman@columbia.edu

    Current design issues:

      . does not properly check implement BREAK handling. Need to figure
        out how to turn a BREAK on and then off based upon receipt of
        COM-PORT Subnegotiations

      . does not properly use select to handle input, output and
        errors on all devices.

      . Lack of login processing

      . Lack of Telnet START_TLS to protect the data stream

      . Lack of Telnet AUTHENTICATION

      . LineState processing is not implemented

      . The code probably won't compile on most versions of Unix due to the
        highly platform dependent nature of the serial apis.

    Fixed in 2.0.0:

      . Telnet DO ECHO should not be refused.  The modem handles the echoing
        if necessary.

      . Cisco IOS returns 0 to the client when INBOUND flow control is SET but
        not supported seperately from OUTBOUND.

      . Track the state of the telnet negotiations

      . Add support for BINARY mode translations

   Fixed in 2.1.0:

      . GetPortFlowControl should return 1 to indicate NO FLOW CONTROL 
        instead of 0.  
  
      . The Cisco IOS hack should become activated only if set by command-
        line option [-i].
      
      . Changed the order of checks in the EscWriteChar function for slightly
        better performance

   Fixed in 2.2.0:

      Mario Viara

      Email: mario@viara.info

      . Fixed set port data size now work with 5 6 7 8 bits.
      . Add version in get signature.

      Russell Coker <russell@coker.com.au> 

      . Many minor changes and code cleanup
      
      For other important changes from Russell Coker see the README file.
        
*/

/* Return NoError, which is 0, on success */

/* Standard library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <termios.h>
#include <termio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Version id */
#define VersionId "2.2.1"
#define SRedirdVersionId "Version " VersionId ", 20 February 2004"

/* Locking constants */
#define LockOk 0
#define Locked 1
#define LockKo 2

/* Error conditions constants */
#define NoError 0
#define Error 1
#define OpenError -1

/* Maximum length of temporary strings */
#define TmpStrLen 255

/* Buffer size */
#define BufferSize 2048

/* File mode and file length for HDB (ASCII) stile lock file */
#define LockFileMode 0644
#define HDBHeaderLen 11

/* Base Telnet protocol constants (STD 8) */
#define TNSE ((unsigned char) 240)
#define TNNOP ((unsigned char) 241)
#define TNSB ((unsigned char) 250)
#define TNWILL ((unsigned char) 251)
#define TNWONT ((unsigned char) 252)
#define TNDO ((unsigned char) 253)
#define TNDONT ((unsigned char) 254)
#define TNIAC ((unsigned char) 255)

/* Base Telnet protocol options constants (STD 27, STD 28, STD 29) */
#define TN_TRANSMIT_BINARY ((unsigned char) 0)
#define TN_ECHO ((unsigned char) 1)
#define TN_SUPPRESS_GO_AHEAD ((unsigned char) 3)

/* Base Telnet Com Port Control (CPC) protocol constants (RFC 2217) */
#define TNCOM_PORT_OPTION ((unsigned char) 44)

/* CPC Client to Access Server constants */
#define TNCAS_SIGNATURE ((unsigned char) 0)
#define TNCAS_SET_BAUDRATE ((unsigned char) 1)
#define TNCAS_SET_DATASIZE ((unsigned char) 2)
#define TNCAS_SET_PARITY ((unsigned char) 3)
#define TNCAS_SET_STOPSIZE ((unsigned char) 4)
#define TNCAS_SET_CONTROL ((unsigned char) 5)
#define TNCAS_NOTIFY_LINESTATE ((unsigned char) 6)
#define TNCAS_NOTIFY_MODEMSTATE ((unsigned char) 7)
#define TNCAS_FLOWCONTROL_SUSPEND ((unsigned char) 8)
#define TNCAS_FLOWCONTROL_RESUME ((unsigned char) 9)
#define TNCAS_SET_LINESTATE_MASK ((unsigned char) 10)
#define TNCAS_SET_MODEMSTATE_MASK ((unsigned char) 11)
#define TNCAS_PURGE_DATA ((unsigned char) 12)

/* CPC Access Server to Client constants */
#define TNASC_SIGNATURE ((unsigned char) 100)
#define TNASC_SET_BAUDRATE ((unsigned char) 101)
#define TNASC_SET_DATASIZE ((unsigned char) 102)
#define TNASC_SET_PARITY ((unsigned char) 103)
#define TNASC_SET_STOPSIZE ((unsigned char) 104)
#define TNASC_SET_CONTROL ((unsigned char) 105)
#define TNASC_NOTIFY_LINESTATE ((unsigned char) 106)
#define TNASC_NOTIFY_MODEMSTATE ((unsigned char) 107)
#define TNASC_FLOWCONTROL_SUSPEND ((unsigned char) 108)
#define TNASC_FLOWCONTROL_RESUME ((unsigned char) 109)
#define TNASC_SET_LINESTATE_MASK ((unsigned char) 110)
#define TNASC_SET_MODEMSTATE_MASK ((unsigned char) 111)
#define TNASC_PURGE_DATA ((unsigned char) 112)

/* Modem state effective change mask */
#define ModemStateECMask ((unsigned char) 255)

#define LineStateECMask ((unsigned char) 255)

/* Default modem state polling in milliseconds (100 msec should be enough) */
#define ModemStatePolling 100

/* Standard boolean definition */
typedef enum { False, True } Boolean;

/* Cisco IOS bug compatibility */
Boolean CiscoIOSCompatible = False;

/* Buffer structure */
typedef
  struct
    {
      unsigned char Buffer[BufferSize];
      unsigned int RdPos;
      unsigned int WrPos;
    }
  BufferType;

/* Complete lock file pathname */
static char * LockFileName;

/* Complete device file pathname */
static char * DeviceName;

/* True when the device has been opened */
Boolean DeviceOpened = False;

/* Device file descriptor */
int DeviceFd;

/* Com Port Control enabled flag */
Boolean TCPCEnabled = False;

/* True after retrieving the initial settings from the serial port */
Boolean InitPortRetrieved = False;

/* Initial serial port settings */
struct termios InitialPortSettings;

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
static unsigned char ModemStateMask = ((unsigned char) 255);

/* Line state mask set by the client */
static unsigned char LineStateMask = ((unsigned char) 0);

#ifdef COMMENT
/* Current status of the line control lines */
static unsigned char LineState = ((unsigned char) 0);
#endif

/* Current status of the modem control lines */
static unsigned char ModemState = ((unsigned char) 0);

/* Break state flag */
Boolean BreakSignaled = False;

/* Input flow control flag */
Boolean InputFlow = True;

/* Telnet State Machine */
static
  struct _tnstate
    {
      int sent_will:1;
      int sent_do:1;
      int sent_wont:1;
      int sent_dont:1;
      int is_will:1;
      int is_do:1;
    }
  tnstate[256];

/* Function prototypes */

/* initialize Telnet State Machine */
void InitTelnetStateMachine(void);

/* Initialize a buffer for operation */
void InitBuffer(BufferType * B);

/* Check if the buffer is empty */
Boolean IsBufferEmpty(BufferType * B);

/* Check if the buffer is full */
Boolean IsBufferFull(BufferType * B);

/* Add a byte to a buffer */
void AddToBuffer(BufferType * B, unsigned char C);

/* Get a byte from a buffer */
unsigned char GetFromBuffer(BufferType * B);

/* Generic log function with log level control. Uses the same log levels
of the syslog(3) system call */
void LogMsg(int LogLevel, const char * const Msg);

/* Try to lock the file given in LockFile as pid LockPid using the classical
HDB (ASCII) file locking scheme */
int HDBLockFile(char * LockFile, pid_t LockPid);

/* Remove the lock file created with HDBLockFile */
void HDBUnlockFile(char * LockFile, pid_t LockPid);

/* Function executed when the program exits */
void ExitFunction(void);

/* Function called on many signals */
void SignalFunction(int unused);

/* Function called on break signal */
void BreakFunction(int unused);

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
unsigned char GetModemState(int PortFd,unsigned char PMState);

/* Set the serial port data size */
void SetPortDataSize(int PortFd, unsigned char DataSize);

/* Set the serial port parity */
void SetPortParity(int PortFd, unsigned char Parity);

/* Set the serial port stop bits size */
void SetPortStopSize(int PortFd, unsigned char StopSize);

/* Set the port flow control and DTR and RTS status */
void SetPortFlowControl(int PortFd,unsigned char How);

/* Set the serial port speed */
void SetPortSpeed(int PortFd, unsigned long BaudRate);

/* Send the signature Sig to the client */
void SendSignature(BufferType * B, char * Sig);

/* Write a char to SockFd performing IAC escaping */
void EscWriteChar(BufferType * B, unsigned char C);

/* Redirect char C to PortFd checking for IAC escape sequences */
void EscRedirectChar(BufferType * SockB, BufferType * DevB, int PortFd, unsigned char C);

/* Send the specific telnet option to SockFd using Command as command */
void SendTelnetOption(BufferType * B, unsigned char Command, char Option);

/* Send a string to SockFd performing IAC escaping */
void SendStr(BufferType * B, char * Str);

/* Send the baud rate BR to SockFd */
void SendBaudRate(BufferType * B, unsigned long int BR);

/* Send the flow control command Command */
void SendCPCFlowCommand(BufferType * B, unsigned char Command);

/* Send the CPC command Command using Parm as parameter */
void SendCPCByteCommand(BufferType * B, unsigned char Command, unsigned char Parm);

/* Handling of COM Port Control specific commands */
void HandleCPCCommand(BufferType * B, int PortFd, unsigned char * Command, size_t CSize);

/* Common telnet IAC commands handling */
void HandleIACCommand(BufferType * B, int PortFd, unsigned char * Command, size_t CSize);

/* Write a buffer to SockFd with IAC escaping */
void EscWriteBuffer(BufferType * B, unsigned char * Buffer, unsigned int BSize);

/* initialize Telnet State Machine */
void InitTelnetStateMachine(void)
  {
    int i;
    for (i = 0;i < 256;i++)
      {
        tnstate[i].sent_do = 0;
        tnstate[i].sent_will = 0;
        tnstate[i].sent_wont = 0;
        tnstate[i].sent_dont = 0;
        tnstate[i].is_do = 0;
        tnstate[i].is_will = 0;
      }
  }

/* Initialize a buffer for operation */
void InitBuffer(BufferType * B)
  {
    /* Set the initial buffer positions */
    B->RdPos = 0;
    B->WrPos = 0;
  }

/* Check if the buffer is empty */
Boolean IsBufferEmpty(BufferType * B)
  {
    return((Boolean) B->RdPos == B->WrPos);
  }

/* Check if the buffer is full */
Boolean IsBufferFull(BufferType * B)
  {
    /* We consider the buffer to be filled when there are 100 bytes left
      This is so even a full buffer can safely have escaped characters
      added to it.
    */
    return((Boolean) B->WrPos == (B->RdPos + BufferSize - 101) % BufferSize);
  }

/* Add a byte to a buffer */
void AddToBuffer(BufferType * B, unsigned char C)
  {
    B->Buffer[B->WrPos] = C;
    B->WrPos = (B->WrPos + 1) % BufferSize;
  }

void PushToBuffer(BufferType * B, unsigned char C)
  {
    if (B->RdPos > 0) 
      B->RdPos--; 
    else 
      B->RdPos = BufferSize - 1; 
	   
    B->Buffer[B->RdPos] = C;
  }

/* Get a byte from a buffer */
unsigned char GetFromBuffer(BufferType * B)
  {
    unsigned char C = B->Buffer[B->RdPos];
    B->RdPos = (B->RdPos + 1) % BufferSize;
    return(C);
  }

/* Generic log function with log level control. Uses the same log levels
of the syslog(3) system call */
void LogMsg(int LogLevel, const char * const Msg)
  {
    if (LogLevel <= MaxLogLevel)
      syslog(LogLevel,"%s",Msg);
  }

/* Try to lock the file given in LockFile as pid LockPid using the classical
HDB (ASCII) file locking scheme */
int HDBLockFile(char * LockFile, pid_t LockPid)
  {
    pid_t Pid;
    int FileDes;
    int N;
    char HDBBuffer[HDBHeaderLen + 1];
    char LogStr[TmpStrLen];

    /* Try to create the lock file */
    while ((FileDes = open(LockFile,O_CREAT | O_WRONLY | O_EXCL,LockFileMode)) == OpenError)
      {
        /* Check the kind of error */
        if ((errno == EEXIST) && ((FileDes = open(LockFile,O_RDONLY,0)) != OpenError))
          {
            /* Read the HDB header from the existing lockfile */
            N = read(FileDes,HDBBuffer,HDBHeaderLen);
            close(FileDes);

            /* Check if the header has been read */
            if (N <= 0)
              {
                /* Emtpy lock file or error: may be another application
                was writing its pid in it */
                sprintf(LogStr,"Can't read pid from lock file %s.",LockFile);
                LogMsg(LOG_NOTICE,LogStr);

                /* Lock process failed */
                return(LockKo);
              }

            /* Gets the pid of the locking process */
            HDBBuffer[N] = '\0';
            Pid = atoi(HDBBuffer);

            /* Check if it is our pid */
            if (Pid == LockPid)
              {
                /* File already locked by us */
                sprintf(LogStr,"Read our pid from lock %s.",LockFile);
                LogMsg(LOG_DEBUG,LogStr);

                /* Lock process succeded */
                return(LockOk);
              }

            /* Check if hte HDB header is valid and if the locking process
              is still alive */
            if ((Pid == 0) || ((kill(Pid,0) != 0) && (errno == ESRCH)))
              /* Invalid lock, remove it */
              if (unlink(LockFile) == NoError)
                {
                  sprintf(LogStr,"Removed stale lock %s (pid %d).",
                    LockFile,Pid);
                  LogMsg(LOG_NOTICE,LogStr);
                }
              else
                {
                  sprintf(LogStr,"Couldn't remove stale lock %s (pid %d).",
                     LockFile,Pid);
                  LogMsg(LOG_ERR,LogStr);
                  return(LockKo);
                }
            else
              {
                /* The lock file is owned by another valid process */
                sprintf(LogStr,"Lock %s is owned by pid %d.",LockFile,Pid);
                LogMsg(LOG_INFO,LogStr);

                /* Lock process failed */
                return(Locked);
              }
          }
        else
          {
            /* Lock file creation problem */
            sprintf(LogStr,"Can't create lock file %s.",LockFile);
            LogMsg(LOG_ERR,LogStr);

            /* Lock process failed */
            return(LockKo);
          }
      }

    /* Prepare the HDB buffer with our pid */
    sprintf(HDBBuffer,"%10d\n",(int) LockPid);

    /* Fill the lock file with the HDB buffer */
    if (write(FileDes,HDBBuffer,HDBHeaderLen) != HDBHeaderLen)
      {
        /* Lock file creation problem, remove it */
        close(FileDes);
        sprintf(LogStr,"Can't write HDB header to lock file %s.",LockFile);
        LogMsg(LOG_ERR,LogStr);
        unlink(LockFile);

        /* Lock process failed */
        return(LockKo);
      }

    /* Closes the lock file */
    close(FileDes);

    /* Lock process succeded */
    return(LockOk);
  }

/* Remove the lock file created with HDBLockFile */
void HDBUnlockFile(char * LockFile, pid_t LockPid)
  {
    char LogStr[TmpStrLen];

    /* Check if the lock file is still owned by us */
    if (HDBLockFile(LockFile,LockPid) == LockOk)
      {
        /* Remove the lock file */
        unlink(LockFile);
        sprintf(LogStr,"Unlocked lock file %s.",LockFile);
        LogMsg(LOG_NOTICE,LogStr);
      }
  }

/* Function executed when the program exits */
void ExitFunction(void)
  {
    /* Restores initial port settings */
    if (InitPortRetrieved == True)
      tcsetattr(DeviceFd,TCSANOW,&InitialPortSettings);

    /* Closes the device */
    if (DeviceOpened == True)
      close(DeviceFd);

    /* Closes the sockets */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);

    /* Removes the lock file */
    HDBUnlockFile(LockFileName,getpid());

    /* Program termination notification */
    LogMsg(LOG_NOTICE,"SRedird stopped.");

    /* Closes the log */
    closelog();
  }

/* Function called on many signals */
void SignalFunction(int unused)
  {
    /* Just to avoid compilation warnings */
    /* There's no performance penalty in doing this 
    because this function is almost never called */
    unused = unused;
    
    /* Same as the exit function */
    ExitFunction();
  }

/* Function called on break signal */
/* Unimplemented yet */
void BreakFunction(int unused)
  {
#ifndef COMMENT
    /* Just to avoid compilation warnings */
    /* There's no performance penalty in doing this 
    because this function is almost never called */
    unused = unused;

    /* Same as the exit function */
    ExitFunction();
#else /* COMMENT */

    unsigned char LineState;

    if (BreakSignaled == True)
      {
        BreakSignaled = False;
        LineState = 0;
      }
    else
      {
        BreakSignaled = True;
        LineState = 16;
      }

    /* Notify client of break change */
    if ((LineStateMask & (unsigned char) 16) != 0)
      {
        LogMsg(LOG_DEBUG,"Notifying break change.");
        SendCPCByteCommand(&ToNetBuf,TNASC_NOTIFY_LINESTATE,LineState);
      }
#endif /* COMMENT */
  }

/* Retrieves the port speed from PortFd */
unsigned long int GetPortSpeed(int PortFd)
  {
    struct termios PortSettings;
    speed_t Speed;

    tcgetattr(PortFd,&PortSettings);
    Speed = cfgetospeed(&PortSettings);

    switch (Speed)
      {
        case B50:
          return(50UL);
        case B75:
          return(75UL);
        case B110:
          return(110UL);
        case B134:
          return(134UL);
        case B150:
          return(150UL);
        case B200:
          return(200UL);
        case B300:
          return(300UL);
        case B600:
          return(600UL);
        case B1200:
          return(1200UL);
        case B1800:
          return(1800UL);
        case B2400:
          return(2400UL);
        case B4800:
          return(4800UL);
        case B9600:
          return(9600UL);
        case B19200:
          return(19200UL);
        case B38400:
          return(38400UL);
        case B57600:
          return(57600UL);
        case B115200:
          return(115200UL);
        case B230400:
          return(230400UL);
        case B460800:
          return(460800UL);
        default:
          return(0UL);
      }
  }

/* Retrieves the data size from PortFd */
unsigned char GetPortDataSize(int PortFd)
  {
    struct termios PortSettings;
    tcflag_t DataSize;

    tcgetattr(PortFd,&PortSettings);
    DataSize = PortSettings.c_cflag & CSIZE;

    switch (DataSize)
      {
        case CS5:
          return((unsigned char) 5);
        case CS6:
          return((unsigned char) 6);
        case CS7:
          return((unsigned char) 7);
        case CS8:
          return((unsigned char) 8);
        default:
          return((unsigned char) 0);
      }
  }

/* Retrieves the parity settings from PortFd */
unsigned char GetPortParity(int PortFd)
  {
    struct termios PortSettings;

    tcgetattr(PortFd,&PortSettings);

    if ((PortSettings.c_cflag & PARENB) == 0)
      return((unsigned char) 1);

    if ((PortSettings.c_cflag & PARENB) != 0 &&
      (PortSettings.c_cflag & PARODD) != 0)
      return((unsigned char) 2);

    return((unsigned char) 3);
  }

/* Retrieves the stop bits size from PortFd */
unsigned char GetPortStopSize(int PortFd)
  {
    struct termios PortSettings;

    tcgetattr(PortFd,&PortSettings);

    if ((PortSettings.c_cflag & CSTOPB) == 0)
      return((unsigned char) 1);
    else
      return((unsigned char) 2);
  }

/* Retrieves the flow control status, including DTR and RTS status,
from PortFd */
unsigned char GetPortFlowControl(int PortFd, unsigned char Which)
  {
    struct termios PortSettings;
    int MLines;

    /* Gets the basic informations from the port */
    tcgetattr(PortFd,&PortSettings);
    ioctl(PortFd,TIOCMGET,&MLines);

    /* Check wich kind of information is requested */
    switch (Which)
      {
        /* Com Port Flow Control Setting (outbound/both) */
        case 0:
          if (PortSettings.c_iflag & IXON)
            return((unsigned char) 2);
          if (PortSettings.c_cflag & CRTSCTS)
            return((unsigned char) 3);
          return((unsigned char) 1);
        break;

        /* BREAK State  */
        case 4:
          if (BreakSignaled == True)
            return((unsigned char) 5);
          else
            return((unsigned char) 6);
        break;

        /* DTR Signal State */
        case 7:
          if (MLines & TIOCM_DTR)
            return((unsigned char) 8);
          else
            return((unsigned char) 9);
        break;

        /* RTS Signal State */
        case 10:
          if (MLines & TIOCM_RTS)
            return((unsigned char) 11);
          else
            return((unsigned char) 12);
        break;

        /* Com Port Flow Control Setting (inbound) */
        case 13:
          if (PortSettings.c_iflag & IXOFF)
            return((unsigned char) 15);
          if (PortSettings.c_cflag & CRTSCTS)
            return((unsigned char) 16);
          return((unsigned char) 14);
        break;

        default:
          if (PortSettings.c_iflag & IXON)
            return((unsigned char) 2);
          if (PortSettings.c_cflag & CRTSCTS)
            return((unsigned char) 3);
          return((unsigned char) 1);
        break;
      }
  }

/* Return the status of the modem control lines (DCD, CTS, DSR, RNG) */
unsigned char GetModemState(int PortFd,unsigned char PMState)
  {
    int MLines;
    unsigned char MState = (unsigned char) 0;

    ioctl(PortFd,TIOCMGET,&MLines);

    if ((MLines & TIOCM_CAR) != 0)
      MState += (unsigned char) 128;
    if ((MLines & TIOCM_RNG) != 0)
      MState += (unsigned char) 64;
    if ((MLines & TIOCM_DSR) != 0)
      MState += (unsigned char) 32;
    if ((MLines & TIOCM_CTS) != 0)
      MState += (unsigned char) 16;
    if ((MState & 128) != (PMState & 128))
      MState += (unsigned char) 8;
    if ((MState & 64) != (PMState & 64))
      MState += (unsigned char) 4;
    if ((MState & 32) != (PMState & 32))
      MState += (unsigned char) 2;
    if ((MState & 16) != (PMState & 16))
      MState += (unsigned char) 1;

    return(MState);
  }

/* Set the serial port data size */
void SetPortDataSize(int PortFd, unsigned char DataSize)
  {
    struct termios PortSettings;
    tcflag_t PDataSize;

    switch (DataSize)
      {
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

    tcgetattr(PortFd,&PortSettings);
    PortSettings.c_cflag &= ~CSIZE;
    PortSettings.c_cflag |= PDataSize & CSIZE;
    tcsetattr(PortFd,TCSADRAIN,&PortSettings);
  }

/* Set the serial port parity */
void SetPortParity(int PortFd, unsigned char Parity)
  {
    struct termios PortSettings;

    tcgetattr(PortFd,&PortSettings);

    switch (Parity)
      {
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
          LogMsg(LOG_WARNING,"Requested unsupported parity, set to no parity.");
          PortSettings.c_cflag = PortSettings.c_cflag & ~PARENB;
        break;
      }

    tcsetattr(PortFd,TCSADRAIN,&PortSettings);
  }

/* Set the serial port stop bits size */
void SetPortStopSize(int PortFd, unsigned char StopSize)
  {
    struct termios PortSettings;

    tcgetattr(PortFd,&PortSettings);

    switch (StopSize)
      {
        case 1:
          PortSettings.c_cflag = PortSettings.c_cflag & ~CSTOPB;
        break;
        case 2:
          PortSettings.c_cflag = PortSettings.c_cflag | CSTOPB;
        break;
        case 3:
          PortSettings.c_cflag = PortSettings.c_cflag & ~CSTOPB;
          LogMsg(LOG_WARNING,"Requested unsupported 1.5 bits stop size, set to 1 bit stop size.");
        break;
        default:
          PortSettings.c_cflag = PortSettings.c_cflag & ~CSTOPB;
        break;
      }

    tcsetattr(PortFd,TCSADRAIN,&PortSettings);
  }

/* Set the port flow control and DTR and RTS status */
void SetPortFlowControl(int PortFd,unsigned char How)
  {
    struct termios PortSettings;
    int MLines;

    /* Gets the base status from the port */
    tcgetattr(PortFd,&PortSettings);
    ioctl(PortFd,TIOCMGET,&MLines);

    /* Check which settings to change */
    switch (How)
      {
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
          tcsendbreak(PortFd,1);
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
          LogMsg(LOG_WARNING,"Inbound flow control ignored.");
        break;
        default:
          LogMsg(LOG_WARNING,"Requested unsupported flow control.");
        break;
      }

    tcsetattr(PortFd,TCSADRAIN,&PortSettings);
    ioctl(PortFd,TIOCMSET,&MLines);
  }

/* Set the serial port speed */
void SetPortSpeed(int PortFd, unsigned long BaudRate)
  {
    struct termios PortSettings;
    speed_t Speed;

    switch (BaudRate)
      {
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
        case 460800UL:
          Speed = B460800;
        break;
        default:
          LogMsg(LOG_WARNING,"Unknwon baud rate requested, setting to 9600.");
          Speed = B9600;
        break;
      }

    tcgetattr(PortFd,&PortSettings);
    cfsetospeed(&PortSettings,Speed);
    cfsetispeed(&PortSettings,Speed);
    tcsetattr(PortFd,TCSADRAIN,&PortSettings);
  }

/* Send the signature Sig to the client */
void SendSignature(BufferType * B, char * Sig)
  {
    AddToBuffer(B,TNIAC);
    AddToBuffer(B,TNSB);
    AddToBuffer(B,TNCOM_PORT_OPTION);
    AddToBuffer(B,TNASC_SIGNATURE);
    SendStr(B,Sig);
    AddToBuffer(B,TNIAC);
    AddToBuffer(B,TNSE);
  }

/* Write a char to socket performing IAC escaping */
void EscWriteChar(BufferType * B, unsigned char C)
  {
    /* Last received byte */
    static unsigned char Last=0;

    if (C == TNIAC)
      AddToBuffer(B,C);
    else
      if (C != 0x0A && !tnstate[TN_TRANSMIT_BINARY].is_will && Last == 0x0D)
        AddToBuffer(B,0x00);
    AddToBuffer(B,C);

    /* Set last received byte */
    Last = C;
  }

/* Redirect char C to Device checking for IAC escape sequences */
void EscRedirectChar(BufferType * SockB, BufferType * DevB, int PortFd, unsigned char C)
  {
    /* Last received byte */
    static unsigned char Last = 0;

    /* Check the IAC escape status */
    switch (IACEscape)
      {
        /* Normal status */
        case IACNormal:
          if (C == TNIAC)
            IACEscape = IACReceived;
          else
            if (!tnstate[TN_TRANSMIT_BINARY].is_do && C == 0x00 && Last == 0x0D)
              /* Swallow the NUL after a CR if not receiving BINARY */
              break;
            else
              AddToBuffer(DevB,C);
        break;

        /* IAC previously received */
        case IACReceived:
          if (C == TNIAC)
            {
              AddToBuffer(DevB,C);
              IACEscape = IACNormal;
            }
          else
            {
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
          if (IACCommand[1] == TNSB)
            {
              /* Get the suboption signature */
              if (IACPos < 4)
                {
                  IACCommand[IACPos] = C;
                  IACPos++;
                }
              else
                {
                  /* Check which suboption we are dealing with */
                  switch (IACCommand[3])
                    {
                      /* Signature, which needs further escaping */
                      case TNCAS_SIGNATURE:
                        switch (IACSigEscape)
                          {
                            case IACNormal:
                              if (C == TNIAC)
                                IACSigEscape = IACReceived;
                              else
                                if (IACPos < TmpStrLen)
                                  {
                                    IACCommand[IACPos] = C;
                                    IACPos++;
                                  }
                            break;

                            case IACComReceiving:
                              IACSigEscape = IACNormal;
                            break;

                            case IACReceived:
                              if (C == TNIAC)
                                {
                                  if (IACPos < TmpStrLen)
                                    {
                                      IACCommand[IACPos] = C;
                                      IACPos++;
                                    }
                                  IACSigEscape = IACNormal;
                                }
                              else
                                {
                                  if (IACPos < TmpStrLen)
                                    {
                                      IACCommand[IACPos] = TNIAC;
                                      IACPos++;
                                    }

                                  if (IACPos < TmpStrLen)
                                    {
                                      IACCommand[IACPos] = C;
                                      IACPos++;
                                    }

                                  HandleIACCommand(SockB,PortFd,IACCommand,IACPos);
                                  IACEscape = IACNormal;
                                }
                            break;
                          }
                      break;

                      /* Set baudrate */
                      case TNCAS_SET_BAUDRATE:
                        IACCommand[IACPos] = C;
                        IACPos++;

                        if (IACPos == 10)
                          {
                            HandleIACCommand(SockB,PortFd,IACCommand,IACPos);
                            IACEscape = IACNormal;
                          }
                      break;

                      /* Flow control command */
                      case TNCAS_FLOWCONTROL_SUSPEND:
                      case TNCAS_FLOWCONTROL_RESUME:
                        IACCommand[IACPos] = C;
                        IACPos++;

                      if (IACPos == 6)
                        {
                          HandleIACCommand(SockB,PortFd,IACCommand,IACPos);
                          IACEscape = IACNormal;
                        }
                      break;

                      /* Normal CPC command with single byte parameter */
                      default:
                        IACCommand[IACPos] = C;
                        IACPos++;

                        if (IACPos == 7)
                          {
                            HandleIACCommand(SockB,PortFd,IACCommand,IACPos);
                            IACEscape = IACNormal;
                          }
                      break;
                    }
                }
            }
          else
            {
              /* Normal 3 byte IAC option */
              IACCommand[IACPos] = C;
              IACPos++;

              if (IACPos == 3)
                {
                  HandleIACCommand(SockB,PortFd,IACCommand,IACPos);
                  IACEscape = IACNormal;
                }
            }
        break;
      }

    /* Set last received byte */
    Last = C;
  }

/* Send the specific telnet option to SockFd using Command as command */
void SendTelnetOption(BufferType * B, unsigned char Command, char Option)
  {
    unsigned char IAC = TNIAC;

    AddToBuffer(B,IAC);
    AddToBuffer(B,Command);
    AddToBuffer(B,Option);
  }

/* Send a string to SockFd performing IAC escaping */
void SendStr(BufferType * B, char * Str)
  {
    size_t I;
    size_t L;

    L = strlen(Str);

    for (I = 0; I < L;I++)
      EscWriteChar(B,(unsigned char) Str[I]);
  }

/* Send the baud rate BR to Buffer */
void SendBaudRate(BufferType *B, unsigned long int BR)
  {
    unsigned char *p;
    unsigned long int NBR;
    int i;

    NBR = htonl(BR);

    AddToBuffer(B,TNIAC);
    AddToBuffer(B,TNSB);
    AddToBuffer(B,TNCOM_PORT_OPTION);
    AddToBuffer(B,TNASC_SET_BAUDRATE);
    p = (unsigned char *) &NBR;
    for (i = 0;i < (int) sizeof(NBR);i++)
      EscWriteChar(B,p[i]);
    AddToBuffer(B,TNIAC);
    AddToBuffer(B,TNSE);
  }

/* Send the flow control command Command */
void SendCPCFlowCommand(BufferType *B, unsigned char Command)
  {
    AddToBuffer(B,TNIAC);
    AddToBuffer(B,TNSB);
    AddToBuffer(B,TNCOM_PORT_OPTION);
    AddToBuffer(B,Command);
    AddToBuffer(B,TNIAC);
    AddToBuffer(B,TNSE);

    if (Command == TNASC_FLOWCONTROL_SUSPEND)
      LogMsg(LOG_DEBUG,"Sent flow control suspend command.");
    else
      LogMsg(LOG_DEBUG,"Sent flow control resume command.");
  }

/* Send the CPC command Command using Parm as parameter */
void SendCPCByteCommand(BufferType *B, unsigned char Command, unsigned char Parm)
  {
    AddToBuffer(B,TNIAC);
    AddToBuffer(B,TNSB);
    AddToBuffer(B,TNCOM_PORT_OPTION);
    AddToBuffer(B,Command);
    EscWriteChar(B,Parm);
    AddToBuffer(B,TNIAC);
    AddToBuffer(B,TNSE);
  }

/* Handling of COM Port Control specific commands */
void HandleCPCCommand(BufferType *SockB, int PortFd, unsigned char * Command, size_t CSize)
  {
    char LogStr[TmpStrLen];
    char SigStr[TmpStrLen];
    unsigned long int BaudRate;
    unsigned char DataSize;
    unsigned char Parity;
    unsigned char StopSize;
    unsigned char FlowControl;

    /* Check wich command has been requested */
    switch (Command[3])
      {
        /* Signature */
        case TNCAS_SIGNATURE:
          if (CSize == 6)
            {
              /* Void signature, client is asking for our signature */
              sprintf(SigStr,"SRedird %s %s",VersionId,DeviceName);
              SendSignature(SockB,SigStr);
              sprintf(LogStr,"Sent signature: %s",SigStr);
              LogMsg(LOG_INFO,LogStr);
            }
          else
            {
              /* Received client signature */
              strncpy(SigStr,(char *) &Command[4],CSize - 6);
              snprintf(LogStr,sizeof(LogStr)-1,"Received client signature: %s",SigStr);
	      LogStr[sizeof(LogStr)-1] = 0;
              LogMsg(LOG_INFO,LogStr);
            }
        break;

        /* Set serial baud rate */
        case TNCAS_SET_BAUDRATE:
          /* Retrieve the baud rate which is in network order */
          BaudRate = ntohl(*((unsigned long int *) &Command[4]));

          if (BaudRate == 0)
            /* Client is asking for current baud rate */
            LogMsg(LOG_DEBUG,"Baud rate notification received.");
          else
            {
              /* Change the baud rate */
              sprintf(LogStr,"Port baud rate change to %lu requested.",BaudRate);
              LogMsg(LOG_DEBUG,LogStr);
              SetPortSpeed(PortFd,BaudRate);
            }

          /* Send confirmation */
          BaudRate = GetPortSpeed(PortFd);
          SendBaudRate(SockB,BaudRate);
          sprintf(LogStr,"Port baud rate: %lu",BaudRate);
          LogMsg(LOG_DEBUG,LogStr);
        break;

        /* Set serial data size */
        case TNCAS_SET_DATASIZE:
          if (Command[4] == 0)
            /* Client is asking for current data size */
            LogMsg(LOG_DEBUG,"Data size notification requested.");
          else
            {
              /* Set the data size */
              sprintf(LogStr,"Port data size change to %u requested.",
                (unsigned int) Command[4]);
              LogMsg(LOG_DEBUG,LogStr);
              SetPortDataSize(PortFd,Command[4]);
            }

          /* Send confirmation */
          DataSize = GetPortDataSize(PortFd);
          SendCPCByteCommand(SockB,TNASC_SET_DATASIZE,DataSize);
          sprintf(LogStr,"Port data size: %u",(unsigned int) DataSize);
          LogMsg(LOG_DEBUG,LogStr);
        break;

        /* Set the serial parity */
        case TNCAS_SET_PARITY:
          if (Command[4] == 0)
            /* Client is asking for current parity */
            LogMsg(LOG_DEBUG,"Parity notification requested.");
          else
            {
              /* Set the parity */
              sprintf(LogStr,"Port parity change to %u requested",
                       (unsigned int) Command[4]);
              LogMsg(LOG_DEBUG,LogStr);
              SetPortParity(PortFd,Command[4]);
            }

          /* Send confirmation */
          Parity = GetPortParity(PortFd);
          SendCPCByteCommand(SockB,TNASC_SET_PARITY,Parity);
          sprintf(LogStr,"Port parity: %u",(unsigned int) Parity);
          LogMsg(LOG_DEBUG,LogStr);
        break;

        /* Set the serial stop size */
        case TNCAS_SET_STOPSIZE:
          if (Command[4] == 0)
            /* Client is asking for current stop size */
            LogMsg(LOG_DEBUG,"Stop size notification requested.");
          else
            {
              /* Set the stop size */
              sprintf(LogStr,"Port stop size change to %u requested.",
                       (unsigned int) Command[4]);
              LogMsg(LOG_DEBUG,LogStr);
              SetPortStopSize(PortFd,Command[4]);
            }

          /* Send confirmation */
          StopSize = GetPortStopSize(PortFd);
          SendCPCByteCommand(SockB,TNASC_SET_STOPSIZE,StopSize);
          sprintf(LogStr,"Port stop size: %u",(unsigned int) StopSize);
          LogMsg(LOG_DEBUG,LogStr);
        break;

        /* Flow control and DTR/RTS handling */
        case TNCAS_SET_CONTROL:
          switch (Command[4])
            {
              case 0:
              case 4:
              case 7:
              case 10:
              case 13:
                /* Client is asking for current flow control or DTR/RTS status */
                LogMsg(LOG_DEBUG,"Flow control notification requested.");
                FlowControl = GetPortFlowControl(PortFd,Command[4]);
                SendCPCByteCommand(SockB,TNASC_SET_CONTROL,FlowControl);
                sprintf(LogStr,"Port flow control: %u",(unsigned int) FlowControl);
                LogMsg(LOG_DEBUG,LogStr);
              break;

              case 5:
                /* Break command */
                tcsendbreak(PortFd,1);
                BreakSignaled = True;
                LogMsg(LOG_DEBUG,"Break Signal ON.");
                SendCPCByteCommand(SockB,TNASC_SET_CONTROL,Command[4]);
              break;

              case 6:
                BreakSignaled = False;
                LogMsg(LOG_DEBUG,"Break Signal OFF.");
                SendCPCByteCommand(SockB,TNASC_SET_CONTROL,Command[4]);
              break;

              default:
                /* Set the flow control */
                sprintf(LogStr,"Port flow control change to %u requested.",(unsigned int) Command[4]);
                LogMsg(LOG_DEBUG,LogStr);
                SetPortFlowControl(PortFd,Command[4]);

                /* Flow control status confirmation */
                if (CiscoIOSCompatible && Command[4] >= 13 && Command[4] <=16)
                  /* INBOUND not supported separately.
                    Following the behavior of Cisco ISO 11.3
                  */
                  FlowControl = 0;
                else
                  /* Return the actual port flow control settings */
                  FlowControl = GetPortFlowControl(PortFd,0);

                SendCPCByteCommand(SockB,TNASC_SET_CONTROL,FlowControl);
                sprintf(LogStr,"Port flow control: %u",(unsigned int) FlowControl);
                LogMsg(LOG_DEBUG,LogStr);
              break;
            }
        break;

        /* Set the line state mask */
        case TNCAS_SET_LINESTATE_MASK:
          sprintf(LogStr,"Line state set to %u",(unsigned int) Command[4]);
          LogMsg(LOG_DEBUG,LogStr);

          /* Only break notification supported */
          LineStateMask = Command[4] & (unsigned char) 16;
          SendCPCByteCommand(SockB,TNASC_SET_LINESTATE_MASK,LineStateMask);
        break;

        /* Set the modem state mask */
        case TNCAS_SET_MODEMSTATE_MASK:
          sprintf(LogStr,"Modem state mask set to %u",(unsigned int) Command[4]);
          LogMsg(LOG_DEBUG,LogStr);
          ModemStateMask = Command[4];
          SendCPCByteCommand(SockB,TNASC_SET_MODEMSTATE_MASK,ModemStateMask);
        break;

        /* Port flush requested */
        case TNCAS_PURGE_DATA:
          sprintf(LogStr,"Port flush %u requested.",(unsigned int) Command[4]);
          LogMsg(LOG_DEBUG,LogStr);
          switch (Command[4])
            {
              /* Inbound flush */
              case 1:
                tcflush(PortFd,TCIFLUSH);
              break;
              /* Outbound flush */
              case 2:
                tcflush(PortFd,TCOFLUSH);
              break;
              /* Inbound/outbound flush */
              case 3:
                tcflush(PortFd,TCIOFLUSH);
              break;
            }

          SendCPCByteCommand(SockB,TNASC_PURGE_DATA,Command[4]);
        break;

        /* Suspend output to the client */
        case TNCAS_FLOWCONTROL_SUSPEND:
          LogMsg(LOG_DEBUG,"Flow control suspend requested.");
          InputFlow = False;
        break;

        /* Resume output to the client */
        case TNCAS_FLOWCONTROL_RESUME:
          LogMsg(LOG_DEBUG,"Flow control resume requested.");
          InputFlow = True;
        break;

        /* Unknown request */
        default:
          sprintf(LogStr,"Unhandled request %u",(unsigned int) Command[3]);
          LogMsg(LOG_DEBUG,LogStr);
        break;
    }
  }

/* Common telnet IAC commands handling */
void HandleIACCommand(BufferType * SockB, int PortFd, unsigned char * Command, size_t CSize)
  {
    char LogStr[TmpStrLen];

    /* Check which command */
    switch(Command[1])
      {
        /* Suboptions */
        case TNSB:
          if (!(tnstate[Command[2]].is_will || tnstate[Command[2]].is_do))
            break;

          switch (Command[2])
            {
              /* RFC 2217 COM Port Control Protocol option */
              case TNCOM_PORT_OPTION:
                HandleCPCCommand(SockB,PortFd,Command,CSize);
              break;

              default:
                sprintf(LogStr,"Unknown suboption received: %u", (unsigned int) Command[2]);
                LogMsg(LOG_DEBUG,LogStr);
              break;
            }
        break;

        /* Requests for options */
        case TNWILL:
          switch (Command[2])
            {
              /* COM Port Control Option */
              case TNCOM_PORT_OPTION:
                LogMsg(LOG_INFO,"Telnet COM Port Control Enabled (WILL).");
                TCPCEnabled = True;
                if (!tnstate[Command[2]].sent_do)
                  {
                    SendTelnetOption(SockB,TNDO,Command[2]);
                  }
                tnstate[Command[2]].is_do = 1;
              break;

              /* Telnet Binary mode */
              case TN_TRANSMIT_BINARY:
                LogMsg(LOG_INFO,"Telnet Binary Transfer Enabled (WILL).");
                if (!tnstate[Command[2]].sent_do)
                  SendTelnetOption(SockB,TNDO,Command[2]);
                tnstate[Command[2]].is_do = 1;
              break;

              /* Echo request not handled */
              case TN_ECHO:
                LogMsg(LOG_INFO,"Rejecting Telnet Echo Option (WILL).");
                if (!tnstate[Command[2]].sent_do)
                  SendTelnetOption(SockB,TNDO,Command[2]);
                tnstate[Command[2]].is_do = 1;
              break;

              /* No go ahead needed */
              case TN_SUPPRESS_GO_AHEAD:
                LogMsg(LOG_INFO,"Suppressing Go Ahead characters (WILL).");
                if (!tnstate[Command[2]].sent_do)
                  SendTelnetOption(SockB,TNDO,Command[2]);
                tnstate[Command[2]].is_do = 1;
              break;

              /* Reject everything else */
              default:
                sprintf(LogStr,"Rejecting option WILL: %u",(unsigned int) Command[2]);
                LogMsg(LOG_DEBUG,LogStr);
                SendTelnetOption(SockB,TNDONT,Command[2]);
                tnstate[Command[2]].is_do = 0;
              break;
            }
          tnstate[Command[2]].sent_do = 0;
          tnstate[Command[2]].sent_dont = 0;
        break;

        /* Confirmations for options */
        case TNDO:
          switch (Command[2])
            {
              /* COM Port Control Option */
              case TNCOM_PORT_OPTION:
                LogMsg(LOG_INFO,"Telnet COM Port Control Enabled (DO).");
                TCPCEnabled = True;
                if (!tnstate[Command[2]].sent_will)
                  SendTelnetOption(SockB,TNWILL,Command[2]);
                tnstate[Command[2]].is_will = 1;
              break;

              /* Telnet Binary mode */
              case TN_TRANSMIT_BINARY:
                LogMsg(LOG_INFO,"Telnet Binary Transfer Enabled (DO).");
                if (!tnstate[Command[2]].sent_will)
                  SendTelnetOption(SockB,TNWILL,Command[2]);
                tnstate[Command[2]].is_will = 1;
              break;

              /* Echo request handled.  The modem will echo for the user. */
              case TN_ECHO:
                LogMsg(LOG_INFO,"Rejecting Telnet Echo Option (DO).");
                if (!tnstate[Command[2]].sent_will)
                  SendTelnetOption(SockB,TNWILL,Command[2]);
                tnstate[Command[2]].is_will = 1;
              break;

              /* No go ahead needed */
              case TN_SUPPRESS_GO_AHEAD:
                LogMsg(LOG_INFO,"Suppressing Go Ahead characters (DO).");
                if (!tnstate[Command[2]].sent_will)
                  SendTelnetOption(SockB,TNWILL,Command[2]);
                tnstate[Command[2]].is_will = 1;
              break;

              /* Reject everything else */
              default:
                sprintf(LogStr,"Rejecting option DO: %u",(unsigned int) Command[2]);
                LogMsg(LOG_DEBUG,LogStr);
                SendTelnetOption(SockB,TNWONT,Command[2]);
                tnstate[Command[2]].is_will = 0;
              break;
            }
          tnstate[Command[2]].sent_will = 0;
          tnstate[Command[2]].sent_wont = 0;
        break;

        /* Notifications of rejections for options */
        case TNDONT:
          sprintf(LogStr,"Received rejection for option: %u",(unsigned int) Command[2]);
          LogMsg(LOG_DEBUG,LogStr);
          if (tnstate[Command[2]].is_will)
            {
              SendTelnetOption(SockB,TNWONT,Command[2]);
              tnstate[Command[2]].is_will = 0;
            }
          tnstate[Command[2]].sent_will = 0;
          tnstate[Command[2]].sent_wont = 0;
        break;

        case TNWONT:
          if (Command[2] == TNCOM_PORT_OPTION)
            {
              LogMsg(LOG_ERR,"Client doesn't support Telnet COM Port "
                "Protocol Option (RFC 2217), trying to serve anyway.");
            }
          else
            {
              sprintf(LogStr,"Received rejection for option: %u",(unsigned int) Command[2]);
              LogMsg(LOG_DEBUG,LogStr);
            }
          if (tnstate[Command[2]].is_do)
            {
              SendTelnetOption(SockB,TNDONT,Command[2]);
              tnstate[Command[2]].is_do = 0;
            }
          tnstate[Command[2]].sent_do = 0;
          tnstate[Command[2]].sent_dont = 0;
        break;
    }
  }

/* Write a buffer to SockFd with IAC escaping */
void EscWriteBuffer(BufferType * B, unsigned char * Buffer, unsigned int BSize)
  {
    unsigned int I;

    if (BSize > 0)
      for (I = 0;I < BSize;I++)
        {
          if (Buffer[I] == TNIAC)
            AddToBuffer(B,TNIAC);
          AddToBuffer(B,Buffer[I]);
        }
  }

void Usage(void)
{
    /* Write little usage information */
    puts("sredird: RFC 2217 compliant serial port redirector");
    puts(SRedirdVersionId);
    puts("This program should be run only by the inetd superserver");
    puts("Usage: sredird [-i] <loglevel> <device> <lockfile> [pollingterval]");
    puts("-i indicates Cisco IOS Bug compatibility");
    puts("Poll interval is in milliseconds, default is 100, "
          "0 means no polling");

    /* Same on the system log */
    LogMsg(LOG_ERR,"sredird: RFC 2217 compliant serial port redirector.");
    LogMsg(LOG_ERR,SRedirdVersionId);
    LogMsg(LOG_ERR,"This program should be run only by the inetd superserver.");
    LogMsg(LOG_ERR,"Usage: sredird [-i] <loglevel> <device> <lockfile> [pollingterval]");
    LogMsg(LOG_ERR,"-i indicates Cisco IOS Bug compatibility");
    LogMsg(LOG_ERR,"Poll interval is in milliseconds, default is 100, 0 means no polling.");
}

/* Main function */
int main(int argc, char * argv[])
  {
    /* Input fd set */
    fd_set InFdSet;

    /* Output fd set */
    fd_set OutFdSet;

    /* Char read */
    unsigned char C;

    /* Temporary string for logging */
    char LogStr[TmpStrLen];

    /* Actual port settings */
    struct termios PortSettings;

    /* Base timeout for stream reading */
    struct timeval BTimeout;

    /* Timeout for stream reading */
    struct timeval RTimeout;

    /* Pointer to timeout structure to set */
    struct timeval * ETimeout = &RTimeout;

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

    /* Out buffer clock ticks limit */
    clock_t MaxBTicks;
    
    /* Optional argument processing indexes */
    int argi = 1;
    int i;

    /* Open the system log */
    openlog("sredird",LOG_PID,LOG_USER);

    /* Check the command line argument count */
    if (argc < 4)
      {
        Usage();
        return(Error);
      }

    /* Process optional switch arguments */
    for (argi = 1;argv[argi][0] == '-' && argi < argc;argi++) 
      {
        i = 1;
        while (argv[argi][i])
          {
            switch (argv[argi][i++])
              {
                /* Cisco IOS compatibility */
                case 'i':
                  if (CiscoIOSCompatible)
                    {
                      /* Already set */
                      Usage();
                      return(Error);
                    }
                  else
                    CiscoIOSCompatible = True;
                break;
                
                default:
                  Usage();
                  return(Error);
                break;
              }
          }
      }

    /* Sets the log level */
    MaxLogLevel = atoi(argv[argi++]);

    /* Gets device and lock file names */
    DeviceName = argv[argi++];
    LockFileName = argv[argi++];

    /* Retrieve the polling interval */
    if (argc == argi + 1)
      {
        BTimeout.tv_sec = 0;
        BTimeout.tv_usec = atol(argv[4]) * 1000;
        MaxBTicks = (BTimeout.tv_usec * CLOCKS_PER_SEC) / (1000 * 1000);

        if (BTimeout.tv_usec <= 0)
          {
            ETimeout = NULL;
            MaxBTicks = 0;
          }
      }
    else
      {
        BTimeout.tv_sec = 0;
        BTimeout.tv_usec = ModemStatePolling * 1000;
        MaxBTicks = (BTimeout.tv_usec * CLOCKS_PER_SEC) / (1000 * 1000);
      }

    /* Logs sredird start */
    LogMsg(LOG_NOTICE,"SRedird started.");

    /* Logs sredird log level */
    sprintf(LogStr,"Log level: %i",MaxLogLevel);
    LogMsg(LOG_INFO,LogStr);

    /* Logs the polling interval */
    sprintf(LogStr,"Polling interval (ms): %u",(unsigned int) (BTimeout.tv_usec / 1000));
    LogMsg(LOG_INFO,LogStr);

    /* Register exit and signal handler functions */
    atexit(ExitFunction);
    signal(SIGHUP,SignalFunction);
    signal(SIGQUIT,SignalFunction);
    signal(SIGABRT,SignalFunction);
    signal(SIGPIPE,SignalFunction);
    signal(SIGTERM,SignalFunction);

    /* Register the function to be called on break condition */
    signal(SIGINT,BreakFunction);

    /* Try to lock the device */
    if (HDBLockFile(LockFileName,getpid()) != LockOk)
      {
        /* Lock failed */
        sprintf(LogStr,"Unable to lock %s. Exiting.",LockFileName);
        LogMsg(LOG_NOTICE,LogStr);
        return(Error);
      }
    else
      {
        /* Lock succeeded */
        sprintf(LogStr,"Device %s locked.",DeviceName);
        LogMsg(LOG_INFO,LogStr);
      }

    /* Open the device */
    if ((DeviceFd = open(DeviceName,O_RDWR | O_NOCTTY | O_NDELAY,0)) == OpenError)
      {
        /* Open failed */
        sprintf(LogStr,"Device in use. Come back later.\r\n");
        LogMsg(LOG_ERR,LogStr);
        sprintf(LogStr,"Unable to open device %s. Exiting.",DeviceName);
        LogMsg(LOG_ERR,LogStr);
        return(Error);
      }
    else
      DeviceOpened = True;

    /* Get the actual port settings */
    tcgetattr(DeviceFd,&InitialPortSettings);
    InitPortRetrieved = True;
    tcgetattr(DeviceFd,&PortSettings);

    /* Set the serial port to raw mode */
    cfmakeraw(&PortSettings);

    /* Enable HANGUP on close and disable modem control line handling */
    PortSettings.c_cflag = (PortSettings.c_cflag | HUPCL) | CLOCAL;

    /* Enable break handling */
    PortSettings.c_iflag = (PortSettings.c_iflag & ~IGNBRK) | BRKINT;

    /* Write the port settings to device */
    tcsetattr(DeviceFd,TCSANOW,&PortSettings);

    /* Reset the device fd to blocking mode */
    if (fcntl(DeviceFd,F_SETFL,fcntl(DeviceFd,F_GETFL) & ~(O_NDELAY)) == OpenError)
      LogMsg(LOG_ERR,"Unable to reset device to non blocking mode, ignoring.");

    /* Initialize the input buffer */
    InitBuffer(&ToDevBuf);
    InitBuffer(&ToNetBuf);

    /* Setup sockets for low latency and automatic keepalive;
     * doesn't check if anything fails because failure doesn't prevent
     * correct functioning but only provides slightly worse behaviour
     */
    SockParm = IPTOS_LOWDELAY;
    setsockopt(STDIN_FILENO,SOL_SOCKET,SO_KEEPALIVE,&SockParmEnable,sizeof(SockParmEnable));
    setsockopt(STDIN_FILENO,SOL_IP,IP_TOS,&SockParm,sizeof(SockParm));
    setsockopt(STDIN_FILENO,SOL_SOCKET,SO_OOBINLINE,&SockParmEnable,sizeof(SockParmEnable));
    setsockopt(STDOUT_FILENO,SOL_SOCKET,SO_KEEPALIVE,&SockParmEnable,sizeof(SockParmEnable));
    setsockopt(STDOUT_FILENO,SOL_IP,IP_TOS,&SockParm,sizeof(SockParm));

    /* Make reads/writes unblocking */
    ioctl(STDOUT_FILENO,FIONBIO,&SockParmEnable);
    ioctl(STDIN_FILENO,FIONBIO,&SockParmEnable);
    ioctl(DeviceFd,FIONBIO,&SockParmEnable);

    /* Send initial Telnet negotiations to the client */
    InitTelnetStateMachine();
    SendTelnetOption(&ToNetBuf,TNWILL,TN_TRANSMIT_BINARY);
    tnstate[TN_TRANSMIT_BINARY].sent_will = 1;
    SendTelnetOption(&ToNetBuf,TNDO,TN_TRANSMIT_BINARY);
    tnstate[TN_TRANSMIT_BINARY].sent_do = 1;
    SendTelnetOption(&ToNetBuf,TNWILL,TN_ECHO);
    tnstate[TN_ECHO].sent_will = 1;
    SendTelnetOption(&ToNetBuf,TNWILL,TN_SUPPRESS_GO_AHEAD);
    tnstate[TN_SUPPRESS_GO_AHEAD].sent_will = 1;
    SendTelnetOption(&ToNetBuf,TNDO,TN_SUPPRESS_GO_AHEAD);
    tnstate[TN_SUPPRESS_GO_AHEAD].sent_do = 1;
    SendTelnetOption(&ToNetBuf,TNDO,TNCOM_PORT_OPTION);
    tnstate[TNCOM_PORT_OPTION].sent_do = 1;

    /* Set up fd sets */
    /* Initially we have to read from all, but we only have data to send
     * to the network */
    FD_ZERO(&InFdSet);
    FD_SET(STDIN_FILENO,&InFdSet);
    FD_SET(DeviceFd,&InFdSet);
    FD_ZERO(&OutFdSet);
    FD_SET(STDOUT_FILENO,&OutFdSet);

    /* Set up timeout for modem status polling */
    if (ETimeout != NULL)
      *ETimeout = BTimeout;

    /* Main loop with fd's control */
    while (True)
      {
        if (select(DeviceFd + 1,&InFdSet,&OutFdSet,NULL,ETimeout) > 0)
          {
            /* Handle buffers in the following order
             *   Error
             *   Output
             *   Input
             * In other words, ensure we can write, make room, read more data
             */

            if (FD_ISSET(DeviceFd,&OutFdSet))
              {
                /* Write to serial port */
                while (!IsBufferEmpty(&ToDevBuf))
                  {
                    int x;
                    C = GetFromBuffer(&ToDevBuf);
                    x = write(DeviceFd,&C,1);
                    if (x < 0 && errno == EWOULDBLOCK)
                      {
                        PushToBuffer(&ToDevBuf,C);
                        break;
                      }
                    else
                      if (x < 1)
                        {
                          LogMsg(LOG_NOTICE,"Error writing to device.");
                          return(NoError);
                        }
                  }
              }

            if (FD_ISSET(STDOUT_FILENO,&OutFdSet))
              {
                /* Write to network */
                while (!IsBufferEmpty(&ToNetBuf))
                  {
                    int x;
                    C = GetFromBuffer(&ToNetBuf);
                    x = write(STDOUT_FILENO,&C,1);
                    if (x < 0 && errno == EWOULDBLOCK)
                      {
                        PushToBuffer(&ToNetBuf,C);
                        break;
                      }
                    else
                      if (x < 1)
                        {
                          LogMsg(LOG_NOTICE,"Error writing to network.");
                          return(NoError);
                        }
                  }
              }

            if (FD_ISSET(DeviceFd,&InFdSet))
              {
                /* Read from serial port */
                while (!IsBufferFull(&ToNetBuf))
                  {
                    int x;
                    x = read(DeviceFd,&C,1);
                    if (x < 0 && errno == EWOULDBLOCK)
                      break;
                    else
                      if (x < 1)
                        {
                          LogMsg(LOG_NOTICE,"Error reading from device.");
                          return(NoError);
                        }
                    EscWriteChar(&ToNetBuf,C);
                  }
              }

            if (FD_ISSET(STDIN_FILENO,&InFdSet))
              {
                /* Read from network */
                while (!IsBufferFull(&ToDevBuf))
                  {
                    int x;
                    x = read(STDIN_FILENO,&C,1);
                    if (x < 0 && errno == EWOULDBLOCK)
                      {
                        break;
                      }
                    else
                      if (x < 1)
                        {
                          LogMsg(LOG_NOTICE,"Error reading from network.");
                          return(NoError);
                        }
                    EscRedirectChar(&ToNetBuf,&ToDevBuf,DeviceFd,C);
                  }
              }

            /* Check if the buffer is not full and remote flow is off */
            if (RemoteFlowOff == True && IsBufferFull(&ToDevBuf) == False)
              {
                /* Send a flow control resume command */
                SendCPCFlowCommand(&ToNetBuf,TNASC_FLOWCONTROL_RESUME);
                RemoteFlowOff = False;
              }
          }

        /* Check the port state and notify the client if it's changed */
        if (TCPCEnabled == True && InputFlow == True)
          {
            if ((GetModemState(DeviceFd,ModemState) & ModemStateMask &
              ModemStateECMask) != (ModemState & ModemStateMask & ModemStateECMask))
              {
                ModemState = GetModemState(DeviceFd,ModemState);
                SendCPCByteCommand(&ToNetBuf,TNASC_NOTIFY_MODEMSTATE,
                  (ModemState & ModemStateMask));
                sprintf(LogStr,"Sent modem state: %u",
                  (unsigned int) (ModemState & ModemStateMask));
                LogMsg(LOG_DEBUG,LogStr);
              }
#ifdef COMMENT
            /* GetLineState() not yet implemented */
            if ((GetLineState(DeviceFd,LineState) & LineStateMask &
                  LineStateECMask) != (LineState & LineStateMask & LineStateECMask))
              {
                LineState = GetLineState(DeviceFd,LineState);
                SendCPCByteCommand(&ToNetBuf,TNASC_NOTIFY_LINESTATE,
                  (LineState & LineStateMask));
                sprintf(LogStr,"Sent line state: %u",
                  (unsigned int) (LineState & LineStateMask));
                LogMsg(LOG_DEBUG,LogStr);
              }
#endif /* COMMENT */
          }

        /* Resets the fd sets */
        FD_ZERO(&InFdSet);

        /* Check if the buffer is not full */
        if (IsBufferFull(&ToDevBuf) == False)
          {
            FD_SET(STDIN_FILENO,&InFdSet);
          }
        else
          if (RemoteFlowOff == False)
            {
              /* Send a flow control suspend command */
              SendCPCFlowCommand(&ToNetBuf,TNASC_FLOWCONTROL_SUSPEND);
              RemoteFlowOff = True;
            }

        /* If input flow has been disabled from the remote client
        don't read from the device */
        if (!IsBufferFull(&ToNetBuf) && InputFlow == True)
          FD_SET(DeviceFd,&InFdSet);

        FD_ZERO(&OutFdSet);
        /* Check if there are characters available to write */
        if (!IsBufferEmpty(&ToDevBuf))
            FD_SET(DeviceFd,&OutFdSet);
        if (!IsBufferEmpty(&ToNetBuf))
            FD_SET(STDOUT_FILENO,&OutFdSet);

        /* Set up timeout for modem status polling */
        if (ETimeout != NULL)
            *ETimeout = BTimeout;
      }
  }
