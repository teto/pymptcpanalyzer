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
from mptcpanalyzer.tshark import TsharkExporter
import pandas as pd
import matplotlib.pyplot as plt
import shlex
import cmd


tshark_bin = "/home/teto/wireshark/run/tshark"

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

# 
#  tshark -T fields -e _ws.col.Source -r /mnt/ntfs/pcaps/demo.pcap
# TODO merge these fields (always) when tshark exports ?
mandatory_fields = [
    'ipsrc',
    'ipdst',
    'sport',
    'dport',
    'mptcpstream',
    'tcpstream',
]

plot_types = ["dsn", "tcpseq", "dss"]

class MpTcpAnalyzer(cmd.Cmd):
    intro = "Press ? to get help"
    prompt = ">"
    def __init__(self, pcap_file):
        super().__init__()
        self.prompt = "%s >" % pcap_file 
# , sep='|'
        self.data = pd.read_csv(pcap_file, sep='|')
        #print(self.data.col
        # list(self.data.columns)
        # TODO run some check on the pcap to check if column names match
        # 

    def do_ls(self, mptcpstream):
        """ list mptcp subflows 
                [mptcp.stream id]
        """
        print(mptcpstream)
        try:
            mptcpstream = int(mptcpstream)
        except ValueError as e:
            print("Expecting the mptcp.stream id as argument")
            return

        print('hello fpr mptcpstream %d' % mptcpstream)
        group = self.data[ self.data.mptcpstream == mptcpstream]
        tcpstreams = group.groupby('tcpstream')
        print("mptcp.stream %d has %d subflow(s): " % (mptcpstream, len(tcpstreams)))
        for tcpstream, gr2 in tcpstreams:
            # print(gr2)
            # print(group['ipsrc'])
            print("\ttcp.stream %d : %s:%d <-> %s:%d" % (
                tcpstream, gr2['ipsrc'].iloc[0], gr2['sport'].iloc[0], gr2['ipdst'].iloc[0], gr2['dport'].iloc[0])
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
    
    # def plot_tcp
    # def plot_mptcp
    # def do_pdsn(self, args):
    def do_plot(self, args):
        """
        Plot DSN vs time
            [mptcp.stream] 
        """
        self.plot_mptcpstream(args)

    def plot_mptcpstream(self, args):
        """
        global member used by others do_plot members *
        """

    # def do_plot_ack(self, args):
    # def do_plot_dss(self, args):
    # todo plot app_latency too

        parser = argparse.ArgumentParser(description='Generate MPTCP stats & plots')
        # parse
        parser.add_argument('field', action="store", choices=plot_types, help='Field to draw (see mptcp_fields.json)')
        parser.add_argument('mptcpstream', action="store", type=int, help='mptcp.stream id')
        parser.add_argument('out', action="store", nargs="?", default="output.png", help='Name of the output file')
        parser.add_argument('--display', action="store_true", help='will display the generated plot')
        # shlex.split(args) ?
        try:
            # args = parser.parse_args( shlex.split(field + ' ' + args))
            args = parser.parse_args( shlex.split(args))
        except SystemExit:
            return

        print(args)
        # returns a DataFrame
        dat = self.data[self.data.mptcpstream == args.mptcpstream]
        if not len(dat.index):
            print("no packet matching mptcp.stream %d" % args.mptcpstream)
            return
        
        tcpstreams = dat.groupby('tcpstream')
        # dssRawDSN could work as well
        # plot (subplots=True)
        fig = plt.figure()
        plt.title("hello world")
        ax = tcpstreams[args.field].plot(ax=fig.gca())
        # for axes in plot:
            # print("Axis ", axes)
            # fig = axes.get_figure()
            # fig.savefig("/home/teto/test.png")
        # fig = plot.get_figure()
        args.out = os.path.join(os.getcwd(), args.out)
        fig.savefig(args.out)
        # os.path.realpath
        # lines, labels = ax1.get_legend_handles_labels()
        cmd="xdg-open %s" % (args.out,) 
        print (cmd) 
        if args.display:
            os.system()


    def do_q(self,*args):
        """
        Quit/exit program
        """
        return True

    def preloop(intro):
        print(intro)

def main():
    parser = argparse.ArgumentParser(
        description='Generate MPTCP stats & plots'
    )
    parser.add_argument("input", action="store", help="Input file that will be converted in csv if needed")
    parser.add_argument("--regen", action="store_true", help="Force the regen")


    # TODO here one could use parse_known_args
    args, unknown_args = parser.parse_known_args(sys.argv[1:])

    basename, ext = os.path.splitext(os.path.basename(args.input))
    csv_filename = basename + ".csv"
   
    if not ext == ".csv":
        print("%s format is not supported as is. Needs to be converted first" % (args.input))
        
        cache = os.path.isfile(csv_filename) 
        if cache:
            print("A cache %s was found" % csv_filename)
        # if matching csv does not exist yet or if generation forced
        if not cache or args.regen:
            log.info("Preparing to convert %s into %s" % (args.input, csv_filename))
            exporter = TsharkExporter(tshark_bin)
            retcode, stderr = exporter.export_to_csv(args.input, csv_filename)
            print("exporter exited with code=", retcode)
            if retcode:
                raise Exception(stderr)
    
    log.info(" %s " % (args.input))
    
    # here I want to generate automatically the csv file 
    analyzer = MpTcpAnalyzer(csv_filename)
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
