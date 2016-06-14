mailPI
======

> mail PI, here to check your alibi.
  
Open its own UDP connection to the configured DNS,  
and craft its own DNS query packet.  
  
Will look for the right MX and ask him the right question,  
"*does this mail really exist ?*".  
  
Alas, all MX are not reliable.

How to
------

- Runs on Python 2.7, using native libraries
- Import the mailPI_conf library for configuration data
- Provide the DNS IP in mailPI_conf (*DNSIP* variable)
- If wanted/required, change the fake address used to communicate with the MX (*FAKADDR* variable)
- Provide the targeted addresses in mailPI itself (*MAILADDRS* variable)
- Launch

Results
-------

> Positive example  
> contact@yahoo.de: EXISTS (according to mx-eu.mail.am0.yahoodns.net) 
>  
> Negative example  
> lorem@ipsum.com: NOT EXIST (according to alt1.aspmx.l.google.com)  
>  
> Error example  
> error: number of answer elements: 0  
> warning: no valid MX answer(not okayheader)

Warning
-------

**Bruteforcing addresses and spamming MX servers will probably get you banned for a while or may raise some flags in a security monitoring tool**

Honesty
-------

250 is a positive answer, 550 a firm negative one, others exist (error codes mostly).  
Telling the truth or lying, both sides have good and bad reasons for.

- Gmail: honest  (does exist: 250 ; does not exist: 550)
- Hotmail: honest (does exist: 250 ; does not exist: 550)
- Orange: honest (does exist: 250 ; does not exist: 550)
- 10 min mail: honest (does exist: 250 ; does not exist: 550)
- YAHOO: lie (does exist: 250 ; does not exist : 250)
- Corporate server : varies according to configuration (everybody exists, nobody exists, or the truth)
- ...

Todo list
---------

- Manage non-forwarding DNS (extract the new DNS query target and send a new query)
- Check for other bugs in the answers extraction)
- Reuse the original query to check the query embedded in the answer
- Avoid so many conversion between binary/hexa/regular value
- Optimize the quantity of data provided to the functions
- Automated local DNS configuration detection and parsing (or, in a nutshell, DNS auto-configuration)
