Introduction
------------

This script is a modified version of the the packet_sniffer_shay.py
that came with SPSE course.
  
  
##### Differences from the original script:  
1. The code was simplified, some functions were refactored, improved
formatting.  
2. To improve readability the code was divided onto 3 modules:
  * sniff_socket.py
  * utils.py
  * packet_sniffer.py
3. This version takes into account the fact that IP header maye be
larger than 20 bytes.
4. This version doesn't parse TCP header options.
5. Script works under both Python 2.7 and 3.2

Usage
-----
To dump in/out HTTP traffic from/to 192.168.1.15 to the console:

```
python packet_sniffer.py host 192.168.1.15 tcp port 80
```

Author
------
Oleg Mitrofanov (reider-roque) 2015

References
----------
IP reference: http://www.networksorcery.com/enp/protocol/ip.htm  
TCP reference: http://www.networksorcery.com/enp/protocol/tcp.htm  
Ethernet frame header format: http://en.wikipedia.org/wiki/Ethernet_frame  
IP header format: http://en.wikipedia.org/wiki/IPv4  
TCP header format: http://en.wikipedia.org/wiki/Transmission_Control_Protocol  
