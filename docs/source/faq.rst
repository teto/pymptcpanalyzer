
FAQ
==========

How to customize my plots ?
Most plots rely on a matplotlib. http://matplotlib.org/users/style_sheets.html

1. What if I have several versions of wireshark installed ?
Copy the config.example in the repository in `$XDG_CONFIG_HOME/mptcpanalyzer/config` and set
the *tshark_binary* value to the full path towards the tshark version that supports mptcp dissection.

2. tshark complains about a corrupted pcap
For instance `tshark: The file "/home/user/file.pcap" appears to have been cut short in the middle of a packet.`
Analyze your pcap with https://f00l.de/pcapfix/.

3. I have matplotlib problems.

    from PyQt4 import QtCore, QtGui
ImportError: No module named 'PyQt4'
http://matplotlib.org/faq/usage_faq.html#what-is-a-backend


4. It doesn't work, what should I do ?
launch 
To debug matplotlib at the same time, add the flags:
verbose-helpful or --verbose-debug 
