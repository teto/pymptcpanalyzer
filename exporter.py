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
import subprocess
import logging
import sys
# from mptcpanalyzer import *
# , load_fields_to_export_from_file
# fields_dict, 
# import sqlite3 as sql
# from core import
from mptcpanalyzer.tshark import TsharkExporter, convert_csv_to_sql

log = logging.getLogger(__name__)

# CONFIG
#########################


def get_basename(fullname, ext):
    return os.path.splitext(os.path.basename(fullname))[0] + "." + ext


# todo should be able to 
# -o force an option, else we can set a profile like -C <profileName>
tshark_exe = "tshark"

def main():

    # https://docs.python.org/3/library/argparse.html#module-argparse
    # http://tricksntweaks.blogspot.be/2013/05/advance-argument-parsing-in-python.html
    parser = argparse.ArgumentParser(
        description='Generate MPTCP stats & plots',
        fromfile_prefix_chars='@',
    )
    parser.add_argument('--relative', action="store_true", help="set to export relative TCP seq number")
    parser.add_argument('--tshark', dest="tshark_exe", action="store", default="/usr/bin/wireshark", type=argparse.FileType('r'), help="Path to shark binary")
    # parser.add_argument('--config', action="store", default=False, help="Can load config from file")

    # readconfigFromFile

    # TODO tshark.py devrait plutot accepter des streams
    # argparse.FileType('r')
    # parser.add_argument('xpconfig', default="tests.ini", action="store", type=str,  help="Config filename. Describe experiment settings")

    # parser.add_argument('inputPcap', action="store", help="src IP")

    pcap_parser = argparse.ArgumentParser(
        description='Expecting pcap file as input',
        add_help=False,
    )
    pcap_parser.add_argument('inputPcap', action="store", help="Input pcap")

    subparsers = parser.add_subparsers(dest="subparser_name", title="Subparsers", help='sub-command help')

    subparser_csv = subparsers.add_parser('pcap2csv', parents=[pcap_parser], help='Converts pcap to a csv file')
    # subparser_csv.add_argument('inputPcap', action="store", help="Input pcap")
    subparser_csv.add_argument('--output', "-o", action="store", help="csv filename")
    subparser_csv.add_argument('--filter', "-f", action="store", help="Filter", default="")
    subparser_csv.add_argument('fields_filename', type=argparse.FileType('r'), action="store", help="json file mapping name to their wireshark name")

    # List MPTCP connections and subflows
    sp_csv2sql = subparsers.add_parser('csv2sql', help='Imports csv file to an sqlite database')
    sp_csv2sql.add_argument('inputCsv', action="store", help="Input Csv")
    sp_csv2sql.add_argument('output', nargs="?", action="store", help="db filename")

    sp_pcap2sql = subparsers.add_parser('pcap2sql', help='Converts pcap to an sqlite database')
    sp_pcap2sql.add_argument('inputPcap', action="store", help="Input pcap")
    sp_pcap2sql.add_argument('output', nargs="?", action="store", help="db filename")

    # parent
    # subparser_list = subparsers.add_parser('list', help='List MPTCP connections and subflows and saves them to a csv file',aliases=["l"])
    # subparser_list.add_argument('db', action="store", help="Input sql")
    # subparser_list.add_argument('outputCsv',  action="store", help="sql filename")

    # subparser_query = subparsers.add_parser('query', help='Run an SQL query',aliases=["q"])
    # subparser_query.add_argument('db', action="store", help="could be csv or sql")
    # parser_list.add_argument('outputCsv', action="store",  help="src IP")

    # subparser_plot = subparsers.add_parser('plot', help='Run an SQL query',aliases=["q"])
    # subparser_plot.add_argument('connectionCsv', action="store", help="Csv file that describes connection")

    args = parser.parse_args(sys.argv[1:])
    # if args.subparser_name == "list":
    #     list_mptcp_connections(args.db)
    # if(args.tosql):
    #   convert_csv_to_sql( "connections.csv",args.tosql,"connections")

    # elif args.subparser_name == "query":
    #     print("query")

    # fields_to_export = load_fields_to_export_from_file("fields_to_export.json")
    # print(fields_to_export)
    # sys.exit(0)

    exporter = TsharkExporter(tshark_exe)
    # exporter.tcp_relative_seq = args.relative if args.relative else True
    exporter.tcp_relative_seq = args.relative 
    # exporter.fields_to_export = fields_to_export

    log.debug("Relative #seq = %s" % exporter.tcp_relative_seq)
    if args.subparser_name == "pcap2csv":
        inputFilename = args.inputPcap
        outputFilename = args.output if args.output else get_basename(inputFilename, "csv")
        fields_to_export = load_fields_to_export_from_file(args.fields_filename)
        exporter.filter = args.filter
        print(fields_to_export)
        exporter.export_pcap_to_csv(inputFilename, outputFilename, fields_to_export)
    elif args.subparser_name == "csv2sql":
        inputFilename = args.inputCsv
        outputFilename = get_basename(inputFilename, "sqlite")
        convert_csv_to_sql(inputFilename, outputFilename, "connections")
    elif args.subparser_name == "pcap2sql":
        inputFilename = args.inputPcap
        outputFilename = get_basename(inputFilename, "sqlite")
        exporter.export_pcap_to_sql(inputFilename, outputFilename)
    else:
        parser.print_help()

#plot dsn

if __name__ == '__main__':
    main()
