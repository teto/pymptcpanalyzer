#!/usr/bin/env python3
###########################################################
# author: Matthieu coudron , matthieu.coudron@lip6.fr
# this script requires wireshark (& gnuplot >4.6) to be installed
# http://stackoverflow.com/questions/11500469/plotting-columns-by-calling-their-header-with-gnuplot
# import csv
# TODO rename into util
import sys
import argparse
import logging
import os
import glob
# import sqlite3 as sql
# from mptcpanalyzer.core import build_csv_header_from_list_of_fields
# from mptcpanalyzer import fields_to_export
from mptcpanalyzer.sqlite_helpers import MpTcpDatabase

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())

# subparsers that need an mptcp_stream should inherit this parser
stream_parser = argparse.ArgumentParser(
    description='',
    # else conflicts with
    add_help=False
)

stream_parser.add_argument("mptcp_stream", action="store", type=int, help="identifier of the MPTCP stream")

# TODO ca le generer des scripts dans le dossier plot
plot_types = {
    'mappings_simple': "plots/mappings/mappings_per_subflow.plot",
    'mappings_time': "plots/mappings/time_vs_mappings.plot",
    # this one uses multiplot
    'mappings_ack': "plots/mappings/mappings_and_ack.plot",
    # 'mptcp_rtt': '',
} 


# TODO renomemr ce script en util ?
# available plots ?
# definir dans la classe plot un parser générique
# faudrait nettoyer ca
plot_types = glob.glob("plots/*.py")


def main():
    parser = argparse.ArgumentParser(
        description='Generate MPTCP stats & plots'
    )

    # argparse.FileType('r')
    parser.add_argument("sqlite_file", type=str, action="store", help="file")

    # parser.add_argument("pcap_file", action="store", help="file")
    subparsers = parser.add_subparsers(dest="subparser_name", title="Subparsers", help='sub-command help')

    # TODO set as parent the one with mptcp stream
    # parser.add_argument("mptcp_stream", action="store", help="identifier of the MPTCP stream")
    # SubParser_mapping
    sp_list_sf = subparsers.add_parser('list_subflows', parents=[stream_parser], help='To csv')
    subparsers.add_parser('list_connections', help='List MPTCP stream by id')
    sp_plot = subparsers.add_parser('plot', parents=[stream_parser], help='Plots')
    sp_plot.add_argument('--out', action="store", default="output.png", help='Name of the output file')
    sp_plot.add_argument('--display', action="store_true", help='will display the generated plot')
    # sp_plot.add_argument('plot_type', choices=plot_types.keys(), help='List of available plots')
    sp_plot.add_argument('plot_type', choices=plot_types, help='List of available plots')
    # plot_subparsers = sp_plot.add_subparsers(dest="subparser_name", title="Subparsers", help='sub-command help')
    # for plot_name, callback in plot_types.items():
    #     sp_plot = plot_subparsers.add_parser(plot_name, parents=[stream_parser], help='To csv')
    # sp_list_sf.set_defaults(cb=MpTcpDatabase.list_subflows)
    # subparsers.add_argument('plot', help='To csv')
    # sp_list_sf = sp_list_sf.set_defaults(func=list_subflows)

    # subparser_csv.add_argument('inputPcap', action="store", help="Input pcap")
    # subparser_csv.add_argument('output', nargs="?", action="store", help="csv filename")
    # subparser_csv.add_argument('--relative', action="store", help="set to export relative TCP seq number")

    # TODO here one could use parse_known_args
    args = parser.parse_args(sys.argv[1:])

    db = MpTcpDatabase(args.sqlite_file)

    if args.subparser_name == "list_subflows":
        # if args.subparser_name == "pcap2csv":
        # subflows = 
        client, server, tcp_connections = db.list_subflows(args.mptcp_stream)
        print("From client to server:")
        # print("Client subflows", client)
        # print("Server subflows", server)

        for sf in client:
            print("{src} -> {dst}".format(
                src=(sf.ip4src + ":" + sf.srcport).ljust(20),
                # srcport=sf['srcport'],
                dst=(sf.ip4dst + ":" + sf.dstport).ljust(20),
                # dstport=sf['dstport'],
            ))
            # print("Stream id {id} between {src} and {dst}".format(
            #     id=sf['tcpstream'],
            #     src=sf['ip4src'],
            #     dst=sf['ip4dst'],
            # ))

    elif args.subparser_name == "list_connections":
        for mptcpstream in db.list_mptcp_connections():
            # TODO add starting times ? 
            print(mptcpstream)

    elif args.subparser_name == "plot":
        # args.
        # plot_script = os.path.join(plot_types[args.plot_type])
        plot_script = args.plot_type

        print("plot_script", plot_script)
        # generated_data_filename = db.plot_subflows_as_datasets(args.mptcp_stream)
        # import plot_script
        # request les streams
        # mptcp_stream
        # save uniflow as files
        # generated_data_filename = db.plot_subflows_as_datasets(args.mptcp_stream)
        # log.info("Dataset saved into file %s" % generated_data_filename)
        # cmd = "gnuplot -e \"datafile='{datafile}'\" {plot}".format(
        #     datafile=generated_data_filename,
        #     plot=plot_script,
        # )
        # print(cmd)
        # # %s" % plot_type
        # if args.display:
        #     # "plots/"+

        #     os.system(cmd)
        #     os.system("eog %s" % "output.png")

    else:
        print("unknown command")


if __name__ == '__main__':
    main()
