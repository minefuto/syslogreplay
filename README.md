# syslogreplay
A tool for sending syslog packet from stdin or syslog file.

This is useful when testing the syslog server by the following functions.
- send syslog packet interactively from stdin
- reproduce syslog transmission interval from syslog file
- source IP address spoofing
- select the source/destination  udp port
- convert syslog's timestamp to current time

## Usage
**This tool requires the administrative privileges.**
```
$ syslogreplay -h
Usage:
  syslogreplay [option] dest-address [src-address]

Option:
  -c    Convert syslog's timestamp to the current timestamp
  -d uint
        Specify the destination port (default 514)
  -f string
        Specify the syslog format (default "rfc3164")
  -s uint
        Specify the source port (default 514)

Format:
  rfc3164         : Jan _2 15:04:05
  rfc5424         : 2006-01-02T15:04:05Z07:00
  rfc5424TenMilli : 2006-01-02T15:04:05.00Z07:00
  rfc5424Milli    : 2006-01-02T15:04:05.000Z07:00
  rfc5424Micro    : 2006-01-02T15:04:05.000000Z07:00
```

- from stdin
<img src="https://github.com/minefuto/syslogreplay/blob/main/gif/fromstdin.gif">

- from syslog file
<img src="https://github.com/minefuto/syslogreplay/blob/main/gif/fromsyslogfile.gif">

## Installation
```
go install github.com/minefuto/syslogreplay@latest
```
Required: gcc, libpcap

## Supported OS
Linux
