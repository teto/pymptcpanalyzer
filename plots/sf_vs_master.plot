# Plots subflows seq numbers vs MPTCP seq numbers as a function of time
# Skips first line of the csv (expect headers)
# 1 column is time
# 2 colum expected to be MPTCP #seq
# Following columns 
# Expects 1 parameter:
# - list of subflow csv files as "file1 file2 file3"
# 
# So you need to run this as for instance
# gnuplot -e "files='subflow0002.csv subflow0003.csv subflow004.csv' " sf_vs_master.plot
# 
#  Author: Matthieu Coudron
# 
# To obtain the correct files, I first exported to CSV from my custom wireshark
# Then I run csvfix like this:
# csvfix file_split -f 6 -fp subflow ~/analyzer/dump_strip.csv
# TODO set to pdf
set terminal png size 800,500
set output "test.png"

set datafile separator "," 

set xlabel "Time"
set ylabel "Sequence number"

# to redirect to a file ?
#set print "stringvar.tmp"

# put here the column index
x_axis=1
tcpstreamid_col=6
#mptcpstreamid_col=7

# MPTCP #seq
mptcp_seq=17
mptcp_seq=5

# start of subflows seq number
# first_subflow_seq_col=16
subflow_seq_col=16
subflow_seq_col=5
# TODO not stdin but rather pass filenames as parameters
# Have a look here on how to loop in gnuplot
# http://stackoverflow.com/questions/14946530/loop-structure-inside-gnuplot

#plot '/dev/stdin' using ($2):( $4==1 && $6==-1 ? $3 : 1/0) :
# syntax "every ::2" skips first line
#plot '/dev/stdin' every ::2 using x_axis:mptcp_seq  with linespoints pointtype 4 title "MPTCP (relative) #seq"

print "hello world"
# files='subflow0002.csv subflow0003.csv subflow004.csv'
#  outfile = sprintf('animation/bessel%03.0f.png',t)
 # set output outfile
#http://stackoverflow.com/questions/18591986/loop-over-array-in-gnuplot
# i=0:words(files, j)
#i=0:words(files, j)
# http://gnuplot-tricks.blogspot.be/2010/01/plot-iterations-and-pseudo-files.html
number_of_subflows=1
do for [file in files] { 
	plot file using (Column()):(subflow_seq_col)  with linespoints pointtype 3 title "Subflow ".file."(relative) #seq"
}

# print