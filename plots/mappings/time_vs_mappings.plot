#!/usr/bin/env gnuplot

load "plots/common.plot"

# datafile = 'mappings.multi.csv'
# datafile = 'test.dat'




set xlabel 'Time (ms)' font ",16"
set ylabel '# DSN' font ",16"

# nooutput
stats datafile every ::1

# plot for [i=1:STATS_blocks] datafile index (i-1) pt 7 ps 2 title 'record '.i
# plot for [IDX=1:STATS_blocks] datafile index IDX u 1:2 w lines title "hello"

# splot '< sqlite3 healy.db3 "SELECT lon,lat,-depth FROM healy_summary WHERE depth IS NOT NULL;" | tr "|" " "' t 'depth'
# we remove 1 because our script adds 2 lines 
# pt = point type
# ps 

# show style arrow

set style line 1 lt rgb "cyan" lw 3 pt 6
set style line 1 lt rgb "red" lw 3 pt 6

set palette model RGB defined ( 0 'red', 1 'green', 2 'blue' )

unset key
unset colorbox

#http://stackoverflow.com/questions/8717805/vary-point-color-in-gnuplot-based-on-value-of-one-column
# column(-2) returns the dataset id
plot datafile every 1:1 using (column("packetid")):(column('mapping_dsn')):(0):(column("mapping_length")):(column(-2)) with vectors filled head palette
# plot datafile index (IDX) using (column("packetid")):(column('mapping_dsn')):(0):(column("mapping_length")) with vectors arrowstyle 1 ls (IDX+1) 
# };
