



=== Presentation ===

Mptcpanalyzer is a tool conceived to help with MPTCP pcap analysis. It relies on tshark (terminal version of wireshark) to generate 
It accepts as input a csv file following a proper format. Upon pcap detection, mptcpanalyzer the formats supported by tshark (terminal version of wireshark)

This repository git@bitbucket.org:mattator/mptcpplots.git is a collection of scripts (python/shell/gnuplot) meant to help understanding MPTCP behavior, mainly via plotting graphs.

The workflow, depending on the plot you want, consists in converting a pcap to a csv or sqlite database with a custom version of wireshark. We then export some sqlite requests to a csv format that can be read by its gnuplot script.

=== How to install ===

Hopefully you should be able to install via:
sudo python3.5

python3.5 because of the type hinting features and
You need the following libraries:
- pandas
Install this custom version of wireshark (branch mptcp_assoc):
https://github.com/teto/wireshark


Licensing
===
Though it might be tempting to release under the CRAPL licence (http://matt.might.net/articles/crapl/) due to its uncomplete state, mptcpanalyzer is shamelessly released under the GPLv3 license.


How to use 
===

mptcpanalyzer can run into 3 modes:
- interactive mode (default): an interpreter with some basic completion will accept your commands. There is also some help embedded.
- if a filename is passed as argument, it will load commands from this file
- otherwise, it will consider the unknow arguments as one command, the same that could be used interactively

1. (Optional)Run exporter.py to convert your pcap into either a csv or an sql file.The program will tell you what arguments are needed.
2. Finally run ./graph.py. It expects a trace to work with. If the trace has the form *XXX.pcap* extension, the script will look for its csv counterpart *XXX.pcap.csv*. The program will tell you what arguments are needed. Then you can open the generated graphs.



=== How to develop new plots ? ===

To ease their use, scripts should follow some guidelines:
1. 
TODO

