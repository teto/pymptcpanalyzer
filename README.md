
Presentation 
===

Mptcpanalyzer is a tool conceived to help with MPTCP pcap analysis. It relies on tshark (terminal version of wireshark) to convert pcap to csv files.
It accepts as input a pcap (or csv file following a proper format). Upon pcap detection, mptcpanalyzer the formats supported by tshark (terminal version of wireshark).
Then you have an interpreter with autocompletion that can generate & display plots.



How to install ?
===

Hopefully you should be able to install via:
$ sudo python3.5 -mpip install mptcpanalyzer

If this doesn't work, dependancies are:
- python3.5 was chosen because of its useful type hinting features and
- the data analysis library called pandas (http://pandas.pydata.org/)
- matplotlib
- numpy
- a wireshark version that supports MPTCP dissection. While most of it has been upstreamed, there is still one patch pending. So for now you need to install this custom version of wireshark (branch mptcp_final):
https://github.com/lip6-mptcp/wireshark-mptcp/tree/mptcp_final

License
===
Though it might be tempting to release under the CRAPL licence (http://matt.might.net/articles/crapl/) due to its uncomplete state, mptcpanalyzer is shamelessly released under the GPLv3 license.


How to use 
===

mptcpanalyzer can run into 3 modes:
- interactive mode (default): an interpreter with some basic completion will accept your commands. There is also some help embedded.
- if a filename is passed as argument, it will load commands from this file
- otherwise, it will consider the unknow arguments as one command, the same that could be used interactively

1. (Optional)Run exporter.py to convert your pcap into either a csv or an sql file.The program will tell you what arguments are needed.
2. Finally run ./panda.py. It expects a trace to work with. If the trace has the form *XXX.pcap* extension, the script will look for its csv counterpart *XXX.pcap.csv*. The program will tell you what arguments are needed. Then you can open the generated graphs.



How to develop new plots ?
===

To ease their use, scripts should follow some guidelines:
1. 
TODO

