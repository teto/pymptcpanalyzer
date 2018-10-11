
FAQ
==========

How to customize my plots ?
Most plots rely on a matplotlib. http://matplotlib.org/users/style_sheets.html

1. What if I have several versions of wireshark installed ?
Adjust your `PATH` so that your version appears first

2. tshark complains about a corrupted pcap
For instance `tshark: The file "/home/user/file.pcap" appears to have been cut short in the middle of a packet.`
Either regenerate a clean pcap or fix your pcap with https://f00l.de/pcapfix/.

3. I have matplotlib problems.

    from PyQt4 import QtCore, QtGui
ImportError: No module named 'PyQt4'
http://matplotlib.org/faq/usage_faq.html#what-is-a-backend


4. It doesn't work, what should I do ?
To debug matplotlib at the same time, add the flags:
verbose-helpful or --verbose-debug 
