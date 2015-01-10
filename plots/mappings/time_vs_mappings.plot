#!/usr/bin/env gnuplot

load "plots/common.plot"

# datafile = 'mappings.multi.csv'
# datafile = 'test.dat'




set xlabel 'Time (ms)' font ",16"
set ylabel '# DSN' font ",16"

# nooutput
stats datafile every ::2

# plot for [i=1:STATS_blocks] datafile index (i-1) pt 7 ps 2 title 'record '.i
# plot for [IDX=1:STATS_blocks] datafile index IDX u 1:2 w lines title "hello"

# splot '< sqlite3 healy.db3 "SELECT lon,lat,-depth FROM healy_summary WHERE depth IS NOT NULL;" | tr "|" " "' t 'depth'
# we remove 1 because our script adds 2 lines 
# pt = point type
# ps 

# show style arrow

# large / small / <size>
set bars fullwidth
# set grid lt 0 lw 0.5 lc rgb "#ff0000"

set style line 1 lt rgb "cyan" lw 3 pt 6
set style line 1 lt rgb "red" lw 3 pt 6

set palette model RGB defined ( 0 'red', 1 'green', 2 'blue' )

# unset key
unset colorbox

set key autotitle columnhead

#http://stackoverflow.com/questions/8717805/vary-point-color-in-gnuplot-based-on-value-of-one-column
# column(-2) returns the dataset id
# filename screen
# TODO display acks
# title columnheader(1)
# title columnheader(1)
# title  "toto"
do for [i=0:STATS_blocks-1] {
	print("hello world")
	plot datafile index i using "packetid":'mapping_dsn':(0):"mapping_length":(column(-2)) with vectors filled head size screen 0.008,145 palette title sprintf("Mappings from dataset %d", column(-2)), \
		datafile index i using 'packetid':"dataack":(column(-2)) with points lt 1 lw 10 lc palette title sprintf("DACKs from dataset %d", column(-2))
}

#A blank filename (’ ’) specifies that the previous filename should be reused.
	# plot "" using (0):(column('mapping_dsn')):(400):(0) with vectors filled nohead lw 5
	# plot "" every 1:1 using (column("packetid")):(column('mapping_dsn')):(50) with xerrorbars ls 1 lw 4
		

		# notitle
# plot datafile index (IDX) using (column("packetid")):(column('mapping_dsn')):(0):(column("mapping_length")) with vectors arrowstyle 1 ls (IDX+1) 
# };
