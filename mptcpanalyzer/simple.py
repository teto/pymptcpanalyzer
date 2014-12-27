#!/usr/bin/env python3
###########################################################
# author: Matthieu coudron , matthieu.coudron@lip6.fr
# this script requires wireshark (& gnuplot >4.6) to be installed
#
# the aim of this script is to plot window/acks
# at both the MPTCP connection and the subflow level
# (for now 1 MPTCP communication => 1 subflow)
#
# csv module doc: https://docs.python.org/3/library/csv.html

# mptcptrace syntax is not easy to follow. for now we assume that
# - {c2s/s2c}_seq_{id}.csv displays:
#   seconds+usec/ack/subflowId(="color")/0/0/-1
# - connection_{id}.csv 
#    subflowId,IPversion,sport,dport,saddr,daddr
# - {c2s/s2c}_acksize_{id}.csv
#    time/ack/id/0/0/-1

import argparse
# import csv
import os
# import shutil
#import querycsv as q
import subprocess
import logging
import sys
from mptcpanalyzer import fields_dict, get_basename
# import sqlite3 as sql
# from core import
from sqlite_helpers import TsharkExporter
#, convert_csv_to_sql

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
# FileHandler
log.addHandler(logging.StreamHandler())

### CONFIG
#########################

# TODO pass as cl arg
# inputPcap = "/home/teto/pcaps/mptcp167.1407349533.bmL/dump_strip.pcap"
# mptcpSeqCsv = "/home/teto/ns3/c2s_seq_0.csv"
# where to save subflow statistics (into a CSV file)
# subflowSeqCsv = "/home/teto/subflowSeq.csv"

# todo should be able to 
# -o force an option, else we can set a profile like -C <profileName>
tshark_exe = "~/wireshark/release/tshark"

# first erase previous data
# if os.path.isdir(plotsDir):
#     shutil.rmtree(plotsDir)

# os.mkdir(plotsDir)
#os.chdir(plotsDir)




def export_all_subflows_data():
    # # find all connections in that (ideally enabled via -l)
    # with open(subflowsList) as csvfile:
    #   #, quotechar='|'
    #   # csv.reader
    #   # csv.DictReader ( fieldnames=)
    #   subflowReader = csv.DictReader(csvfile, delimiter=',')
    #   for id,subflow in enumerate(subflowReader):
    #       #print(subflow)
    #       export_subflow_data(inputPcap,subflowSeqCsv,filter)
    #       # todo filter from tshark
            
    # # finally I run gnuplot passing the names of the different files
    # # pseudocode
    # # todo have a loop in gnuplot ? in case there are several subflows ?
    # cmd= "gnuplot -e \"mptcpSeqCsv='{mptcpData}';subflowSeqCsv='{subflowSeq}'\" {script} ".format(
    #       script=gnuplotScript,
    #       mptcpData=mptcpSeqCsv,
    #       subflowSeq=subflowSeqCsv
    #   )

    # print(cmd)
    # os.system(cmd)
    pass



# if I use csvfix, I will need the following functions:
# - fix
# - file_split
# - sort 
# - write_multi

# use -o flag to output to a file

# le sort a l'air de bien marcher, dmg qu'il ne presse
# le mptcpstream exporte a l'air d'etre le numero du stream parent ?
# (ou bien en fait certains numéros sont attribués puis 
# ensuite enlevés quand ils sont rattachés a une autre connexion)
# Example
# csvfix sort -rh -f 1:AN <CSV>
# (AN => Ascending Numerically) , -rh (read header)

# csvfix find -f 4 -r 0:0 test.csv (-r => range)

# mptcpstream
# csvfix write_multi

# csvfix write_multi -m 1,2 -rs '\n\n' -smq > test_multi.csv
# 
def main():

    exporter = TsharkExporter(tshark_exe)

    # https://docs.python.org/3/library/argparse.html#module-argparse
    parser = argparse.ArgumentParser(description='Generate MPTCP stats & plots')
    parser.add_argument('--relative', action="store", default=False, help="set to export relative TCP seq number")

    # readconfigFromFile
    #argparse.FileType('r')
    # parser.add_argument('xpconfig', default="tests.ini", action="store", type=str,  help="Config filename. Describe experiment settings")

    # parser.add_argument('inputPcap', action="store", help="src IP")

    subparsers = parser.add_subparsers(dest="subparser_name", title="Subparsers", help='sub-command help')

    subparser_csv = subparsers.add_parser('pcap2csv', help='Converts pcap to a csv file')
    subparser_csv.add_argument('inputPcap', action="store", help="Input pcap")
    subparser_csv.add_argument('output', nargs="?", action="store", help="csv filename")

    # List MPTCP connections and subflows
    sp_csv2sql = subparsers.add_parser('csv2sql', help='Imports csv file to an sqlite database')
    sp_csv2sql.add_argument('inputCsv', action="store", help="Input Csv")
    sp_csv2sql.add_argument('output', nargs="?", action="store", help="db filename")

    sp_pcap2sql = subparsers.add_parser('pcap2sql', help='Converts pcap to an sqlite database')
    sp_pcap2sql.add_argument('inputPcap', action="store", help="Input pcap")
    sp_pcap2sql.add_argument('output', nargs="?", action="store", help="db filename")

    #parent
    # subparser_list = subparsers.add_parser('list', help='List MPTCP connections and subflows and saves them to a csv file',aliases=["l"])
    # subparser_list.add_argument('db', action="store", help="Input sql")
    # subparser_list.add_argument('outputCsv',  action="store", help="sql filename")

    # subparser_query = subparsers.add_parser('query', help='Run an SQL query',aliases=["q"])
    # subparser_query.add_argument('db', action="store", help="could be csv or sql")
    # parser_list.add_argument('outputCsv', action="store",  help="src IP")

    # subparser_plot = subparsers.add_parser('plot', help='Run an SQL query',aliases=["q"])
    # subparser_plot.add_argument('connectionCsv', action="store", help="Csv file that describes connection")

    # subparser_plot.add_argument('type', action="store", choices=["seq"], help="type of plot")

    # parser.add_argument('srcIp', action="store", help="src IP")
    # parser.add_argument('dstIp', action="store", help="dst IP" ) 
    # parser.add_argument('--nat', action="store", help="world") #nat_parser.print_help() )

    args = parser.parse_args(sys.argv[1:])
    # if args.subparser_name == "list":
    #     list_mptcp_connections(args.db)
        # if(args.tosql):
        #   convert_csv_to_sql( "connections.csv",args.tosql,"connections")

    # elif args.subparser_name == "query":
    #     print("query")

    inputFilename = args.inputPcap
    exporter.tcp_relative_seq = args.relative if args.relative else True

    if args.subparser_name == "pcap2csv":
        
        outputFilename = args.output if args.output else get_basename(inputFilename, "csv")
        exporter.export_pcap_to_csv(inputFilename, outputFilename )
    # elif args.subparser_name == "csv2sql":
    #     inputFilename = args.inputPcap
    #     outputFilename = get_basename(inputFilename, "sqlite")
    #     convert_csv_to_sql(inputFilename, outputFilename)
    elif args.subparser_name == "pcap2sql":
        # inputFilename = args.inputPcap
        outputFilename = get_basename(inputFilename, "sqlite")
        exporter.export_pcap_to_sql(inputFilename, outputFilename)
    else:
        parser.print_help()

#plot dsn

if __name__ == '__main__':
    main()
