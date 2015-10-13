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
import mptcpanalyzer
import pandas as pd
import cmd
# from mptcpanalyzer.plot import Plot

# import sqlite3 as sql
# from mptcpanalyzer.core import build_csv_header_from_list_of_fields
# from mptcpanalyzer import fields_to_export
# from mptcpanalyzer.sqlite_helpers import MpTcpDatabase

log = logging.getLogger("mptcpanalyzer")
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
# plot_types = {
#     'mappings_simple': "plots/mappings/mappings_per_subflow.plot",
#     'mappings_time': "plots/mappings/time_vs_mappings.plot",
#     # this one uses multiplot
#     'mappings_ack': "plots/mappings/mappings_and_ack.plot",
#     # 'mptcp_rtt': '',
# } 


class MpTcpAnalyzer(cmd.Cmd):
    intro = "Press ? to get help"
    prompt = ">"
    def __init__(self, pcap_file):
        super().__init__()
        self.prompt = "%s loaded\n>" % pcap_file 
        self.data = pd.read_csv(pcap_file, sep='|')
        
    def do_list_subflows(self, mptcpstream):
        """ list mptcp subflows """
        print('hello fpr mptcpstream %d' % mptcpstream)
        data.groupby("mptcpstream").describe()

    def do_list_mptcp(self, *args):
        """ List mptcp connections """
        print('mptcp connections')
        mp = self.data.groupby("mptcpstream")
        print(mp['ip4src'])
        # le nunique s'applique sur une liste et permet d'avoir
        # mp.ip4src.nth(0)[0]

    def do_plot(self, *args):
        pass

    def do_q(self,*args):
        """
        Quit/exit program
        """
        return True

    def preloop(intro):
        print(intro)

def main():
    print('hello world')
    parser = argparse.ArgumentParser(
        description='Generate MPTCP stats & plots'
    )
    parser.add_argument("pcap_file", action="store", help="file")


    # TODO here one could use parse_known_args
    args, unknown_args = parser.parse_known_args(sys.argv[1:])

    analyzer = MpTcpAnalyzer(args.pcap_file)
    analyzer.cmdloop() 

    # elif args.subparser_name == "plot":
        # # args.
        # # plot_script = os.path.join(plot_types[args.plot_type])

        # plot_script = args.plot_type
        # print("plot_script", plot_script)
        # print("unparsed args", unknown_args)
        # plot = plot_types[args.plot_type](db, unknown_args)

        # ok, output = plot.generate()

        # # Plot.get_available_plots()
        # # Generate such an object

        # # plot.generate()
        # if ok and args.display:
            # cmd = "eog %s" % output
            # os.system(cmd)

        # # generated_data_filename = db.plot_subflows_as_datasets(args.mptcp_stream)
        # # import plot_script

    # else:
        # print("unknown command")
        # # parser.
        # # TODO afficher l'aide


if __name__ == '__main__':
    main()
