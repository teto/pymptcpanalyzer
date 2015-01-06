This repository git@bitbucket.org:mattator/mptcpplots.git is meant to collect gnuplot scripts used to help understanding MPTCP behavior.

To ease their use, scripts should follow some guidelines:
1. explain in the gnuplot script comments the format of the csv file expected
2. provide an example *.csv, the first line of csv should describe each field in the manner: field1,field2,...,field3
3. Each script should reside in its own subfolder
4. Ideally scripts should accept an arbitrary number of subflows

Gnuplot accepts multiple datasets from one



mptcp.stream == 3 and tcp.options.mptcp.datalvllen > 0


columnheader

One can retrieve the number of blocks via the stats  command
http://stackoverflow.com/questions/14823477/how-to-count-the-number-of-indicies-in-a-gnuplot-input-file

Apparently there is a stat package in gnuplot
http://www.gnuplotting.org/manpage-gnuplot-4-6/

http://stackoverflow.com/questions/16743702/gnuplot-draw-a-vertical-line-from-the-x-axis-to-the-plot-and-from-the-plot-to

http://stackoverflow.com/questions/11500469/plotting-columns-by-calling-their-header-with-gnuplot


http://stackoverflow.com/questions/12818797/gnuplot-plotting-several-datasets-with-titles-from-one-file