NmaptoCSV
============

Description
-----------
A simple python script to convert Nmap output to CSV


Features
--------
* Support of Nmap version 5 & 6 normal format output (default format)
* Support of Nmap any version Grepable format output (-oG)

Usage
-----
Pass the Nmap output via stdin or from a specified file (-i).  
The processed dump can be collected at stdout or to a specified file (-o).

### Options
```
$ python nmaptocsv.py -h
Usage: nmaptocsv.py [options]

Options:
  -h, --help            show this help message and exit
  -i INPUT, --input=INPUT
                        Nmap scan output file in normal format (stdin if not
                        specified)
  -o OUTPUT, --output=OUTPUT
                        csv output filename (stdout if not specified)

```

### Nmap normal output (default format)
```
$ nmap -p- 10.0.0.0/24 | python nmaptocsv.py

IP;Port;Protocol;Service;Version
10.0.0.1;21;tcp;ftp
;53;tcp;domain
;80;tcp;http
;110;tcp;pop3
;143;tcp;imap
;443;tcp;ssl/http
10.0.0.3;25;tcp;smtp
;111;tcp;rpcbind
;48175;tcp;
10.0.0.2;5432;tcp;postgresql

```

### Nmap Grepable format (-oG)
```
$ cat scan.gnmap 
# Nmap 6.25 scan initiated Tue Dec 25 15:23:48 2012 as: nmap --reason -A -sV -v -p- -sX -oA scan localhost
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 127.0.0.1 (localhost)	Status: Up
Host: 127.0.0.1 (localhost)	Ports: 80/open/tcp//http?//, 5432/open/tcp//postgresql/PostgreSQL DB 8.4.1 - 8.4.11/	Ignored State: closed (65533)	OS: Linux 2.4.21
# Nmap done at Tue Dec 25 15:24:15 2012 -- 1 IP address (1 host up) scanned in 28.76 seconds


$ python nmaptocsv.py -i scan.gnmap

IP;Port;Protocol;Service;Version
127.0.0.1;80;tcp;http?;
;5432;tcp;postgresql;PostgreSQL DB 8.4.1 - 8.4.11

```

Dependencies
------------
* python >= 2.4


Copyright and license
---------------------
Nmaptocsv is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Nmaptocsv is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nmaptocsv. 
If not, see http://www.gnu.org/licenses/.

Contact
-------
* Thomas Debize < tdebize at mail d0t com >
