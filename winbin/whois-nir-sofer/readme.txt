

WhoisCL v1.90
Copyright (c) 2005 - 2019 Nir Sofer
Web site: http://www.nirsoft.net



Description
===========

WhoisCL is a simple command-line utility that allows you to easily get
information about a registered domain. It automatically connect to the
right WHOIS server, according to the top-level domain name, and retrieve
the WHOIS record of the domain.
It supports both generic domains and country code domains.



System Requirements
===================


* Windows operating system: Windows 98/ME/2000/XP/2003/2008/7/8.
* Internet connection.
* On a firewall, you should allow outgoing connections to port 43.



Versions History
================


* Version 1.90 - Added -s command-line option, which allows you to
  specify the WHOIS server to use instead of taking it from the servers
  list of WhoisCL.
* Version 1.85 - Added support for whois-server-list.xml - You can now
  download the whois servers list xml (whois-server-list.xml) from
  https://github.com/whois-server-list/whois-server-list , put it in the
  same folder of WhoisCL.exe (as whois-server-list.xml file) and WhoisCL
  will automatically extract the right whois server from this file.
* Version 1.81 - Fixed the whois server of .online domains.
* Version 1.80 - Added -1 command-line option. When you use it, WhoisCL
  will send only a single WHOIS request and it won't send WHOIS request
  to a secondary WHOIS server detected in the first WHOIS response.
* Version 1.76 - Added support for .swiss domains.
* Version 1.75 - Added support for .ky domains.
* Version 1.74 - Added the WHOIS servers of .top, .wang , .swiss ,
  .cloud domains.
* Version 1.73 - Added the WHOIS servers of .ai, .aw, .gi, .gg, .mo,
  .ml, .cf, .mz, .ec, .bo, .na, .nc, .rs domains, and more...
* Version 1.72 - Added the whois servers of .hiphop, .pics, and
  .community domains.
* Version 1.71 - Fixed bug: WhoisCL failed to retrieve properly the
  WHOIS information of centralnic.com domains (gb.com and others).
* Version 1.70 - Added support for SOCKS4 and SOCKS5 proxy. (Be aware
  that user/password authentication is currently not supported.)
* Version 1.63 - Added support for .london and .eus domains.
* Version 1.62 - Fixed to display full information for .name domains.
* Version 1.61 - Added support for Donuts domains ( .email, .company,
  .support , and many others...)
* Version 1.60 - Added the WHOIS server of .ac.uk domains.
* Version 1.59 - Added the WHOIS server of .id domains.
* Version 1.58 - Updated the WHOIS servers of .hr, .es, .by, and .tn
  domains.
* Version 1.57 - Added the WHOIS server of .pw and .so domains.
* Version 1.56 - Added the WHOIS server of .ax domains.
* Version 1.55 - Added support for br.com, cn.com, eu.com, hu.com,
  no.com, gb.com, gb.net, qc.com, sa.com, se.com, se.net, us.com, uy.com,
  za.com, uk.com, and uk.net domains.
* Version 1.50 - Added -n command-line option. If you specify this
  option, WhoisCL will get the correct WHOIS server from
  xx.whois-servers.net, instead of using the internal WHOIS servers list.
* Version 1.42 - Added the WHOIS servers of .ke and .io domains.
* Version 1.41 - Fixed a problem of running this tool on Windows 2000.
* Version 1.40 - Fixed the WHOIS server of .ru and .su domains.
* Version 1.38 - Fixed the whois server for .fo, .gl, .gs, .hu, .dz,
  and .ua domains.
* Version 1.37 - Added support for .co domains.
* Version 1.36 - Added support for .tr domains.
* Version 1.35 - Fixed the WHOIS server for .tw domains and added WHOIS
  server for .asia domains.
* Version 1.34 - Added support for .pr domains.
* Version 1.33 - Fixed the whois server of .ms domains.
* Version 1.32 - Updated the whois servers for .is, .lt, .ma, .md, .pl,
  .si, and .sk domains.
* Version 1.31 - Added/Updated the whois servers for .in, .ie, .me,
  .tel, and co.nl domains.
* Version 1.30 - Fixed the whois servers for .at, .be, .bg, .cz, and
  others.
* Version 1.25 - The whois servers file now allows you to specify more
  than one server for country-code level domains. (For example: one
  server for .uk domains and the other server for gov.uk domains)
* Version 1.24 - Fixed the problem WHOIS server of .ro domains and
  fixed the WHOIS server of .cn domains.
* Version 1.23 - Fixed the WHOIS server of .jp domains to whois.jprs.jp
* Version 1.21 - Updated the WHOIS server for .com and .net domains (to
  whois.verisign-grs.com) and for .org domain (to whois.pir.org)
* Version 1.20 - Added support for external WHOIS servers list -
  whois-servers.txt
* Version 1.12 - Fixed the WHOIS server for .tr domains.
* Version 1.11 - Added support for .coop domains.
* Version 1.10 - Added support for the following domains: .ws, .vc,
  .uy, .uz, .tp. .tk, .tl, .sa, .sb, .sc, .pro, .nf, .mc, .mu, .la, .ly,
  .ir, .hm, .hn, .gl, .dm, .cd, .bz, .bj, .bi, .ae, .ag, .my, .mobi.,
  .travel
* Version 1.09 - Added support for .my domains, and changed the .nl
  WHOIS server to the new one.
* Version 1.08 - Added support for .nz domains.
* Version 1.07 - Fixed the WHOIS servers for .mx and .br domains
* Version 1.06 - Fixed the WHOIS server for .ve domains.
* Version 1.05 - Fixed the WHOIS server for .pt domains.
* Version 1.04 - Added support for .eu domains.
* Version 1.03 - Added support for .tv domains.
* Version 1.02 - Fixed the problem with French domains.
* Version 1.01 - Fixed the problem with German domains.
* Version 1.00 - First Release.



Usage
=====

WhoisCL [-r] [-n] [-1] [-s {Server}] [-socks4] [-socks5] Domain



-r
If you specify this option, the top remark lines of the WHOIS record are
automatically removed.

-n
If you specify this option, WhoisCL will get the correct WHOIS server
from xx.whois-servers.net, instead of using the internal WHOIS servers
list.


-1
WhoisCL will send only a single WHOIS request and it won't send WHOIS
request to a secondary WHOIS server detected in the first WHOIS response

-s {Server}
Use the specified WHOIS server instead of using the servers list of
WhoisCL.

-socks4
Specifies SOCKS4 proxy to use, in IPAddress:Port format

-socks5
Specifies SOCKS5 proxy to use, in IPAddress:Port format

Domain
Domain name.

Examples:
WhoisCL microsoft.com
WhoisCL -r google.com
WhoisCL -n w3c.org
WhoisCL -1 -s whois.verisign-grs.com google.com
WhoisCL -socks4 192.168.0.55:1080 nirsoft.net
WhoisCL -socks5 192.168.10.55:9980 facebook.com

Example for WhoisCL output:



WHOIS Server: whois.markmonitor.com



Registrant:
	Google Inc.
	(DOM-258879)
	2400 E. Bayshore Pkwy Mountain View
	CA
	94043 US

    Domain Name: google.com

	Registrar Name: Markmonitor.com
	Registrar Whois: whois.markmonitor.com
	Registrar Homepage: http://www.markmonitor.com

    Administrative Contact:
	DNS Admin
	(NIC-1340142) 
	Google Inc.
	2400 E. Bayshore Pkwy Mountain View
	CA
	94043 US
	dns-admin@google.com +1.6503300100 Fax- +1.6506181499
    Technical Contact, Zone Contact:
	DNS Admin
	(NIC-1340144) 
	Google Inc.
	2400 E. Bayshore Pkwy Mountain View
	CA
	94043 US
	dns-admin@google.com +1.6503300100 Fax- +1.6506181499

    Created on..............: 1997-Sep-15.
    Expires on..............: 2011-Sep-14.
    Record last updated on..: 2005-Jul-25 20:14:20.

    Domain servers in listed order:

    NS3.GOOGLE.COM		
    NS4.GOOGLE.COM		
    NS1.GOOGLE.COM		
    NS2.GOOGLE.COM		

MarkMonitor.com - The Leader in Corporate Domain Management
----------------------------------------------------------
For Global Domain Consolidation, Research & Intelligence,
and Enterprise DNS, go to: www.markmonitor.com
----------------------------------------------------------




Creating whois-servers.txt
==========================

Starting from version 1.20, you can create your own WHOIS servers list to
override the default servers defined by WhoisCL.
In order to use this feature, follow the instructions below:
1. Create a file named 'whois-servers.txt' in the same folder of
   WhoisCL.exe
2. Add the needed servers to the list. Each line should contain the
   domain extension, a space character, and then the whois server
   address. For example:

gov whois.nic.gov
com rs.internic.net 
il whois.isoc.org.il
ir whois.nic.ir


3. In the next time that you run WhoisCL, the specified servers will
   be used instead of the default servers list stored in WhoisCL.
Be aware that WhoisCL only supports WHOIS servers in port 43. It doesn't
support Web-based WHOIS requests.



Using whois-server-list.xml
===========================

Starting from version 1.85, you can download the whois servers list xml
file from https://github.com/whois-server-list/whois-server-list, put the
file as whois-server-list.xml in the same folder of WhoisCL.exe and
WhoisCL will automatically extract the right whois server from this file.



License
=======

This utility is released as freeware. You are allowed to freely
distribute this utility via floppy disk, CD-ROM, Internet, or in any
other way, as long as you don't charge anything for this. If you
distribute this utility, you must include all files in the distribution
package, without any modification !



Disclaimer
==========

The software is provided "AS IS" without any warranty, either expressed
or implied, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose. The author will not
be liable for any special, incidental, consequential or indirect damages
due to loss of data or any other reason.



Feedback
========

If you have any problem, suggestion, comment, or you found a bug in my
utility, you can send a message to nirsofer@yahoo.com
