#!/usr/bin/env python3
###########################################################
# Copyright 2015-2016 Université Pierre et Marie Curie
# author: Matthieu coudron , coudron@lip6.fr

import argparse
import os
import subprocess
import logging
import sys
from mptcpanalyzer.tshark import TsharkConfig

log = logging.getLogger(__name__)

# CONFIG
#########################


def get_basename(fullname, ext):
    return os.path.splitext(os.path.basename(fullname))[0] + "." + ext


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
    parser.add_argument('--tshark', dest="tshark_exe", action="store", default="tshark", help="Path to shark binary")
    parser.add_argument('--profile', dest="tshark_exe", action="store", default=None, 
        help="Wireshark profile which contains many options to customize output")

    # TODO tshark.py devrait plutot accepter des streams
    # argparse.FileType('r')
    # parser.add_argument('xpconfig', default="tests.ini", action="store", type=str,  help="Config filename. Describe experiment settings")

    # parser.add_argument('inputPcap', action="store", help="src IP")

    pcap_parser = argparse.ArgumentParser(
        description='Expecting pcap file as input',
        add_help=False,
    )
    pcap_parser.add_argument('inputPcap', action="store", help="Input pcap")

    subparsers = parser.add_subparsers(dest="subparser_name", title="Subparsers",
        help='sub-command help')


    subparser_csv = subparsers.add_parser('pcap2csv', parents=[pcap_parser], help='Converts pcap to a csv file')
    # subparser_csv.add_argument('inputPcap', action="store", help="Input pcap")
    subparser_csv.add_argument('--output', "-o", action="store", help="csv filename")
    subparser_csv.add_argument('--filter', "-f", action="store", help="Filter", default="")
    subparser_csv.add_argument('fields_filename', type=argparse.FileType('r'), action="store", 
        help="json file mapping name to their wireshark name"
    )

    # List MPTCP connections and subflows
    sp_csv2sql = subparsers.add_parser('csv2sql', help='Imports csv file to an sqlite database')
    sp_csv2sql.add_argument('inputCsv', action="store", help="Input Csv")
    sp_csv2sql.add_argument('output', nargs="?", action="store", help="db filename")

    sp_pcap2sql = subparsers.add_parser('pcap2sql', help='Converts pcap to an sqlite database')
    sp_pcap2sql.add_argument('inputPcap', action="store", help="Input pcap")
    sp_pcap2sql.add_argument('output', nargs="?", action="store", help="db filename")

    args = parser.parse_args(sys.argv[1:])

    exporter = TsharkConfig(tshark_exe, profile=args.profile)
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

if __name__ == '__main__':
    main()
