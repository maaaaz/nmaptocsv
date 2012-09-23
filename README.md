NmaptoCSV
============

Description
-----------
A simple python script to convert Nmap output to CSV


Features
--------
* Support of Nmap version 5 & 6 normal format output (-oA)
* Support of Nmap any version Grepable format output (-oG)

Usage
-----
Pass the Nmap output via stdin or from a specified file (-i)
The processed dump can be collected at stdout or to a specified file (-o)

* Your Nmap normal output from stdin
```
$ nmap -p- 10.0.0.0/24 | python nmaptocsv.py

IPProtocol;Port;Service
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

Dependencies
------------
* python >= 2.6


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

Greetings
---------
* awe
