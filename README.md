

=== Presentation ===

Mptcpanalyzer is a tool conceived to help with MPTCP pcap analysis. It accepts as input the formats supported by tshark (terminal version of

This repository git@bitbucket.org:mattator/mptcpplots.git is a collection of scripts (python/shell/gnuplot) meant to help understanding MPTCP behavior, mainly via plotting graphs.

The workflow, depending on the plot you want, consists in converting a pcap to a csv or sqlite database with a custom version of wireshark. We then export some sqlite requests to a csv format that can be read by its gnuplot script.

=== How to install ===

mptcpanalyzer

You need python3.5

Install this custom version of wireshark (branch mptcp_assoc):
https://github.com/teto/wireshark


=== How to use ===

1. Capture packets (with tcpdump/wireshark for instance)
2. Run exporter.py to convert your pcap into either a csv or an sql file.The program will tell you what arguments are needed.
3. Finally run ./graph.py. The program will tell you what arguments are needed. Then you can open the generated graphs.



=== How to develop new plots ? ===

To ease their use, scripts should follow some guidelines:
1. explain in the gnuplot script comments the format of the csv file expected
2. provide an example *.csv, the first line of csv should describe each field in the manner: field1,field2,...,field3
3. Each script should reside in its own subfolder
4. Scripts should be generic enough

Gnuplot accepts multiple datasets from one



mptcp.stream == 3 and tcp.options.mptcp.datalvllen > 0





=== A few helpers to use gnuplot ===
One can retrieve the number of blocks via the stats  command
http://stackoverflow.com/questions/14823477/how-to-count-the-number-of-indicies-in-a-gnuplot-input-file

Apparently there is a stat package in gnuplot
http://www.gnuplotting.org/manpage-gnuplot-4-6/

http://stackoverflow.com/questions/16743702/gnuplot-draw-a-vertical-line-from-the-x-axis-to-the-plot-and-from-the-plot-to

http://stackoverflow.com/questions/11500469/plotting-columns-by-calling-their-header-with-gnuplot


http://stackoverflow.com/questions/12818797/gnuplot-plotting-several-datasets-with-titles-from-one-file
