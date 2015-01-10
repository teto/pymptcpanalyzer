#!/usr/bin/env gnuplot

load "plots/common.plot"


set xlabel 'Time (ms)' font ",16"
set ylabel '# DSN' font ",16"


set style line 1 lt rgb "cyan" lw 3 pt 6
set style line 1 lt rgb "red" lw 3 pt 6

set palette model RGB defined ( 0 'red', 1 'green', 2 'blue' )

unset key
unset colorbox

#http://stackoverflow.com/questions/8717805/vary-point-color-in-gnuplot-based-on-value-of-one-column
# column(-2) returns the dataset id
# filename screen
plot datafile every 1:1 using (column("packetid")):(column('mapping_dsn')):(0):(column("mapping_length")):(column(-2)) with vectors filled head size screen 0.008,145 palette title "First", \

plot "" using (column('packetid')):(column("dataack")) with points lt 1 lw 10 lc rgb "green"
#A blank filename (’ ’) specifies that the previous filename should be reused.
	# plot "" using (0):(column('mapping_dsn')):(400):(0) with vectors filled nohead lw 5
	# plot "" every 1:1 using (column("packetid")):(column('mapping_dsn')):(50) with xerrorbars ls 1 lw 4
		

		# notitle
# plot datafile index (IDX) using (column("packetid")):(column('mapping_dsn')):(0):(column("mapping_length")) with vectors arrowstyle 1 ls (IDX+1) 
# };
