#!/usr/bin/env python3
###########################################################
# author: Matthieu coudron , matthieu.coudron@lip6.fr
# this script requires wireshark (& gnuplot >4.6) to be installed
# http://stackoverflow.com/questions/11500469/plotting-columns-by-calling-their-header-with-gnuplot
# import csv
# TODO list
# -auto conversion from pcap to csv
# -reenable sql support
# -ability to load filesfrom the interpreter
# -add color with ncurses (problematic with utf8 ?)
import sys
import argparse
import logging
import os
import readline
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


# TODO merge these fields (always) when tshark exports ?
mandatory_fields = [
    'ip4src',
    'ip4dst',
    'sport',
    'dport',
    'mptcpstream',
    'tcpstream',
]

class MpTcpAnalyzer(cmd.Cmd):
    intro = "Press ? to get help"
    prompt = ">"
    def __init__(self, pcap_file):
        super().__init__()
        self.prompt = "%s >" % pcap_file 
# , sep='|'
        self.data = pd.read_csv(pcap_file, sep='|')
        #print(self.data.col
        list(d.columns)
        # TODO run some check on the pcap to check if column names match
        # 

    def do_ls(self, mptcpstream):
        """ list mptcp subflows 
                [mptcp.stream id]
        """
        print(mptcpstream)
        mptcpstream = int(mptcpstream)
        print('hello fpr mptcpstream %d' % mptcpstream)
        group = self.data[ self.data.mptcpstream == mptcpstream]
        tcpstreams = group.groupby('tcpstream')
        print("mptcp.stream %d has %d subflow(s): " % (mptcpstream, len(tcpstreams)))
        for tcpstream, gr2 in tcpstreams:
            print("\ttcp.stream %d : %s:%d <-> %s:%d" % (
                tcpstream, group['ip4src'][0], group['sport'][0], group['ip4dst'][0], group['dport'][0])
                  )

    def do_lc(self, *args):
        """ List mptcp connections """
        print('mptcp connections')
        self.data.describe()
        mp = self.data.groupby("mptcpstream")
        for mptcpstream, group in mp:
            self.do_ls(mptcpstream)
            # print("mptcp.stream %d : %s <-> %s " % (mptcpstream, group['ip4src'][0], group['ip4dst'][0]))
        # print(mp['ip4src'])
        # le nunique s'applique sur une liste et permet d'avoir
        # mp.ip4src.nth(0)[0]

    # def do_plot_ack(self, args):
    # def do_plot_dss(self, args):
    # todo plot app_latency too
    def do_plot_dsn(self, arg):
        """
        Plot DSN vs time
            [mptcp.stream] 
        """
        plot_types = {
        }
        parser = argparse.ArgumentParser(description='Generate MPTCP stats & plots')
        # parse
        parser.add_argument('mptcpstream', action="store", type=int, help='mptcp.stream id')
        parser.add_argument('out', action="store", nargs="?", default="output.png", help='Name of the output file')
        parser.add_argument('--display', action="store_true", help='will display the generated plot')
        # shlex.split(args) ?
        args = parser.parse_args(arg)
        print(args)
        # returns a DataFrame
        dat = self.data[self.data.mptcpstream == args.mptcpstream]
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return



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
