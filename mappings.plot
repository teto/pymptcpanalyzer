#!/usr/bin/env gnuplot

reset

# datafile = 'mappings.multi.csv'
datafile = 'test.dat'

set terminal png size 600,400
# set terminal interactive
set output 'mappings.multi.png'


set datafile separator "|" 
# nooutput
stats datafile every ::1

# plot for [i=1:STATS_blocks] datafile index (i-1) pt 7 ps 2 title 'record '.i
# plot for [IDX=1:STATS_blocks] datafile index IDX u 1:2 w lines title "hello"

# splot '< sqlite3 healy.db3 "SELECT lon,lat,-depth FROM healy_summary WHERE depth IS NOT NULL;" | tr "|" " "' t 'depth'
# we remove 1 because our script adds 2 lines 
# pt = point type
# ps 
do for [IDX=0:STATS_blocks-1] {
# 	set title sprintf("subflow")
	print("hello")
# 	# plot datafile every ::1 index (IDX) arrow from column("mapping_dsn"), IDX to (column("mapping_dsn") + column("mapping_length")), IDX
# 	plot datafile every ::1 using index (IDX) with vectors from 0, 2 to 4, IDX
	plot "test.dat" index (IDX) using (column("mapping_dsn")):(IDX):(column("mapping_length")):(0) with vectors filled head lw 3
};	#title columnhead#every ::1 
# plot for [IDX=0:STATS_blocks-1] "test.dat" index (IDX) using (column("mapping_dsn")):IDX:(column("mapping_length")):0 with vectors filled head lw 3
# plot for [IDX=0:STATS_blocks-1] "test.dat" index (IDX) using (column("packetid")):IDX:(2):0 every ::1 with vectors filled head lw 3
