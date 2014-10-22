#!/usr/bin/env python3
###########################################################
# author: Matthieu coudron , matthieu.coudron@lip6.fr
# this script requires wireshark (& gnuplot) to be installed
#
# the aim of this script is to plot window/acks
# at both the MPTCP connection and the subflow level
# (for now 1 MPTCP communication => 1 subflow)
#
# csv module doc: https://docs.python.org/3/library/csv.html

# mptcptrace syntax is not easy to follow. for now we assume that
# - {c2s/s2c}_seq_{id}.csv displays:
# 	seconds+usec/ack/subflowId(="color")/0/0/-1
# - connection_{id}.csv 
#    subflowId,IPversion,sport,dport,saddr,daddr
# - {c2s/s2c}_acksize_{id}.csv
#    time/ack/id/0/0/-1

import argparse
import csv
import os
import shutil
import querycsv as q
import subprocess
import logging
import sys

log = logging.getLogger( __name__)
log.setLevel(logging.DEBUG)

### CONFIG
#########################
plotsDir 	 = "plots"
subflowsList = "connection_0.csv"
gnuplotScript 		 = "/home/teto/mptcptrace/res/scripts/gnuplot/sf_vs_master.plot"
# TODO pass as cl arg
inputPcap = "/home/teto/pcaps/mptcp167.1407349533.bmL/dump_strip.pcap"
mptcpSeqCsv = "/home/teto/ns3/c2s_seq_0.csv"
# where to save subflow statistics (into a CSV file)
subflowSeqCsv = "/home/teto/subflowSeq.csv"


# first erase previous data
if os.path.isdir(plotsDir):
	shutil.rmtree(plotsDir)

os.mkdir(plotsDir)
#os.chdir(plotsDir)


def get_subflow_csv_output_filename(id):
	pass


def export_subflow_data(inputFilename, outputFilename, filter):
	"""
	return 
	
	In order to be able to use tcp.time_relative and tcp.time_delta, you will
	need
	to enable TCP timestamps. This is disabled by default (for performance
	optimization).
	"""

	fields=("frame.time","tcp.seq","tcp.ack","ip.src","ip.dst")
	# fields=' -e '.join(fields)

	# # for some unknown reasons, -Y does not work so I use -2 -R instead
	# # -E quote=d 
	# cmd="tshark -2 -R '{filterExpression}' -r {inputPcap} -T fields {fieldsExpanded} -E separator=,   > {outputCsv}".format(
	# 			inputPcap=inputFilename,
	# 			outputCsv=outputFilename,
	# 			fieldsExpanded=fields,
	# 			filterExpression=filter
	# 			)
	# run_tshark_command();
	# log.info(cmd)
	# output = subprocess.check_output(cmd);
	# os.system(cmd)
	# return output

	# tshark -r test.pcap -T fields -e frame.number -e eth.src -e eth.dst -e ip.src -e ip.dst -e frame.len > test1.csv

# all the args sys.argv[1:]
# for now let's assume it is run by hand
#os.system("mptcptrace ")

def export_all_subflows_data():
	# # find all connections in that (ideally enabled via -l)
	# with open(subflowsList) as csvfile:
	# 	#, quotechar='|'
	# 	# csv.reader
	# 	# csv.DictReader ( fieldnames=)
	# 	subflowReader = csv.DictReader(csvfile, delimiter=',')
	# 	for id,subflow in enumerate(subflowReader):
	# 		#print(subflow)
	# 		# this is a 2 way filter
	# 		filter="ip.addr eq {ipSrc} and ip.addr eq {ipDst} and tcp.port eq {srcPort} and tcp.port eq {dstPort}".format(
	# 				ipSrc=subflow["saddr"],
	# 				ipDst=subflow["daddr"],
	# 				srcPort=subflow["sport"],
	# 				dstPort=subflow["dport"]
	# 			)
	# 		# print("filter\n",filter)
			
	# 		export_subflow_data(inputPcap,subflowSeqCsv,filter)
	# 		# todo filter from tshark
			
	# # finally I run gnuplot passing the names of the different files
	# # pseudocode
	# # todo have a loop in gnuplot ? in case there are several subflows ?
	# cmd= "gnuplot -e \"mptcpSeqCsv='{mptcpData}';subflowSeqCsv='{subflowSeq}'\" {script} ".format(
	# 		script=gnuplotScript,
	# 		mptcpData=mptcpSeqCsv,
	# 		subflowSeq=subflowSeqCsv
	# 	)

	# print(cmd)
	# os.system(cmd)
	pass


def run_tshark_command(inputFilename,fields,filter=None,outputFilename=None):
	"""
	inputFilename should be pcap filename
	fields should be iterable (tuple, list ...)
	returns outout as a string
	"""
	# fields that tshark should export
	# tcp.seq / tcp.ack / ip.src / frame.number / frame.number / frame.time
	# exhaustive list https://www.wireshark.org/docs/dfref/f/frame.html
	#"tcp.seq",
	# tcp.options.mptcp.mptcpsubflowseqno
	# tcp.options.mptcp.dataseqno
	# tcp.options.mptcp.dataack
	# tcp.options.mptcp.datalvllen
	# tcp.options.mptcp.subtype == 2 => DSS (0 => MP-CAPABLE)
	# to filter connection
	# fields=("frame.time","tcp.seq","tcp.ack","ip.src","ip.dst")
	# fieldsExpanded=' -e '.join(fields)
	# .'"' 
	filter = '-2 -R "%s"'%(filter) if filter else ''
	# for some unknown reasons, -Y does not work so I use -2 -R instead
	# -E quote=d 
	cmd="tshark {filterExpression} -r {inputPcap} -T fields {fieldsExpanded} -E separator=, ".format(
				inputPcap=inputFilename,
				outputCsv=outputFilename,
				fieldsExpanded=' -e '.join(fields),
				filterExpression=filter
				)

	log.info(cmd)

	#https://docs.python.org/3/library/subprocess.html#subprocess.check_output
	output = subprocess.check_output(cmd, shell=True);
	# os.system(cmd)
	# except CalledProcessError as e:
	return output


def list_connections(inputPcap):
	"""
	Returns a dictionary of MPTCP connections
	Fields should be iterable
	"""
	# filter MP_CAPABLE and MP_JOIN suboptions
	filter="tcp.options.mptcp.subtype == 0 "
	#or tcp.options.mptcp.subtype == 1
	# todo export tokens
	fields=("frame.time","tcp.seq","tcp.ack","ip.src","ip.dst",)

	output = run_tshark_command(inputPcap,fields,filter)

	# with
	# could filter
	with open("test.csv","wb") as f:
		f.write(output)
	# print(output.decode('utf-8'))


def save_to_file():
	pass

def main():

	# https://docs.python.org/3/library/argparse.html#module-argparse
	parser = argparse.ArgumentParser(
			description='Generate MPTCP stats & plots'
			)

	# readconfigFromFile
	#argparse.FileType('r')
	# parser.add_argument('xpconfig', default="tests.ini", action="store", type=str,  help="Config filename. Describe experiment settings")

	# parser.add_argument('inputPcap', action="store", help="src IP")
	
	subparsers = parser.add_subparsers(dest="subparser_name", title="Subparsers", help='sub-command help')
	
	parser_list = subparsers.add_parser('list', help='List MPTCP connections and subflows',aliases=["l"])
	parser_list.add_argument('inputPcap', action="store", help="src IP")

	# parser.add_argument('srcIp', action="store", help="src IP")
	# parser.add_argument('dstIp', action="store", help="dst IP" ) 
	# parser.add_argument('--nat', action="store", help="world") #nat_parser.print_help() )

	args = parser.parse_args( sys.argv[1:] )
	if args.subparser_name == "list":
		list_connections(args.inputPcap)



if __name__ == '__main__':
	main()