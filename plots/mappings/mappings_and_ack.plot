#!/usr/bin/env gnuplot
# set loadpath
load "plots/common.plot"

# datafile = 'mappings.multi.csv'
# datafile = 'test.dat'


set key right bottom

set xlabel 'Time (ms)' font ",16"
set ylabel '# DSN' font ",16"

# nooutput
# STATS_min/STATS_max/STATS_blocks
# stats datafile every ::2

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
set style line 2 lt rgb "red" lw 3 pt 6

# 2 'pink', 3 'green',


# unset key
# unset colorbox
# set colorbox
# show palette
# set key autotitle columnhead

#http://stackoverflow.com/questions/8717805/vary-point-color-in-gnuplot-based-on-value-of-one-column
# column(-2) returns the dataset id
# filename screen
# TODO display acks

#palette cb 

# The `set cbrange` command sets the range of values which are colored using
# the current `palette` by styles `with pm3d`, `with image` and `with palette`.
# Values outside of the color range use color of the nearest extreme
# set cbrange[0:STATS_blocks-1]


# http://stackoverflow.com/questions/27901349/different-color-per-dataset
# `lc variable` tells the program to use the value read from one column of the
# input data as a linetype index, and use the color belonging to that linetype

# WARN: column(-2) does not work outside of using
# that's why we explicitly set the bornes instead of using 

# get_client_()
print(server_uniflow(3))
# set label "dataack"
# set label "mapping"
plot for [idx=1:(nb_of_subflows)] \
	client_uniflow(idx) using "reltime":'mapping_dsn':(0):"mapping_length":(idx) with vectors filled head size screen 0.008,145 lt idx title sprintf("Mappings from client %d", idx), \
	server_uniflow(idx) using 'reltime':"dataack":(nb_of_subflows + idx)  with points pt 2 lc palette z title sprintf("DACKs from server %d", idx)

