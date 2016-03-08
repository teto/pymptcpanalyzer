#!/usr/bin/env python
# -*- coding: utf8
# PYTHON_ARGCOMPLETE_OK
# vim: set et fenc=utf-8 ff=unix sts=4 sw=4 ts=4 :

# Copyright 2015-2016 Université Pierre et Marie Curie
# author: Matthieu coudron , matthieu.coudron@lip6.fr

# TODO list
# -ability to load files from the interpreter
# -would like to draw a bar with the repartition of the data between the different subflows with sthg like
#  plot(kind='barh', stacked=True);
# TODO add plugin system
# http://docs.openstack.org/developer/stevedore/
# explaing how argparse to shell completion works;
# http://dingevoninteresse.de/wpblog/?p=176
# https://travelingfrontiers.wordpress.com/2010/05/16/command-processing-argument-completion-in-python-cmd-module/
# the autocomplete plugin seems also nice
import sys
import argparse
import logging
import os
# import glob
from mptcpanalyzer.tshark import TsharkExporter, Filetype
from mptcpanalyzer.plot import Plot
from mptcpanalyzer.config import MpTcpAnalyzerConfig
# import mptcpanalyzer.config
# import config
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import shlex
import cmd
import traceback

from stevedore import extension

log = logging.getLogger("stevedore")
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())

log = logging.getLogger("mptcpanalyzer")
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())

# subparsers that need an mptcp_stream should inherit this parser
stream_parser = argparse.ArgumentParser(
    description='',
    # else conflicts with
    add_help=False
)

stream_parser.add_argument(
    "mptcp_stream", action="store", type=int, help="identifier of the MPTCP stream")

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
    'dsn',
    # 'dss_dsn',
    # 'latency',
    'dack'
]

delimiter = '|'
# should be automatically generated
plot_types = ["dsn", "tcpseq", "dss"]


class MpTcpAnalyzer(cmd.Cmd):
    intro = """
        Welcome in mptcpanalyzer (http://github.com/lip6-mptcp/mptcpanalyzer)
        Press ? to get help
        """
    ruler = "="
    prompt = ">"
    # config = None
    plot_mgr = None
    cmd_mgr = None

    def __init__(self, cfg: MpTcpAnalyzerConfig, pcap_file, input=None):
        """
        """
        # stdin ?
        self.prompt = "%s >" % pcap_file
        self.config = cfg

        ### LOAD PLOTS 
        ######################
# you can have list available plots under the namespace 
# https://pypi.python.org/pypi/entry_point_inspector

        # mgr = driver.DriverManager(
        self.plot_mgr = extension.ExtensionManager(
            namespace='mptcpanalyzer.plots',
            invoke_on_load=True,
            verify_requirements=True,
            invoke_args=(),
            )

        self.cmd_mgr = extension.ExtensionManager(
            namespace='mptcpanalyzer.cmds',
            invoke_on_load=True,
            verify_requirements=True,
            invoke_args=(),
            )

        # TODO we should catch stevedore.exception.NoMatches
        
        def _inject_cmd(ext,data):
            print(ext.name)
            for prefix in ["do", "help", "complete"]:
                method_name = prefix + "_" + ext.name
                # obj2 = getattr(ext.obj, "help_" + ext.name)
                # print(obj)
                try:
                    obj = getattr(ext.obj, prefix)
                    if obj:
                        setattr(MpTcpAnalyzer, method_name, obj)
                except AttributeError:
                    log.debug("Plugin does not provide %s" % method_name)
            # setattr(MpTcpAnalyzer, 'help_stats', _test_help)

        results = self.cmd_mgr.map(_inject_cmd, self)

        # if loading commands from a file, we disable prompt not to pollute
        # output
        if input:
            self.use_rawinput = False
            self.prompt = ""
            self.intro = ""
        super().__init__(completekey='tab', stdin=input)
# , sep='|'
        # there seems to be several improvements a
        # possible to set type of columns with dtype={'b': object, 'c': np.float64}
        # one can choose the column to use as index index_col=
        self.data = pd.read_csv(pcap_file, sep=delimiter)
        columns = list(self.data.columns)
        print(columns)
        for field in mandatory_fields:
            if field not in columns:
                raise Exception(
                    "Missing mandatory field [%s] in csv, regen the file or check the separator" % field)
        #print(self.data.col
        # TODO run some check on the pcap to check if column names match
        #

    # TODO does not work yet
    def require_fields(mandatory_fields: list):  # -> Callable[...]:
        """
        Decorator used to check dataset contains all fields required by function
        """

        def check_fields(self, *args, **kwargs):
            columns = list(self.data.columns)
            # print(columns)
            for field in mandatory_fields:
                if field not in columns:
                    raise Exception(
                        "Missing mandatory field [%s] in csv, regen the file or check the separator" % field)
            func
        return check_fields

    # @require_fields(['sport', 'dport', 'ipdst', 'ipsrc'])
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

        print('hello for mptcpstream %d' % mptcpstream)
        group = self.data[self.data.mptcpstream == mptcpstream]
        tcpstreams = group.groupby('tcpstream')
        print("mptcp.stream %d has %d subflow(s): " %
              (mptcpstream, len(tcpstreams)))
        for tcpstream, gr2 in tcpstreams:
            line = "\ttcp.stream {stream} : {srcip}:{sport} <-> {dstip}:{dport}".format(
                tcpstream=tcpstream, srcip=gr2['ipsrc'].iloc[0], sport=gr2['sport'].iloc[0], 
                dstip=gr2['ipdst'].iloc[0], 
                dport=gr2['dport'].iloc[0]
                )
            print(line)

    def complete_ls(self, text, line, begidx, endidx):
        """ help to complete the args """
        # conversion to set removes duplicate keys
        l = list(set(self.data["mptcpstream"]))
        # convert items to str else it won't be used for completion
        l = [str(x) for x in l]

        return l


    def do_summary(self, mptcpstream):
        """
        Summarize contributions of each subflow
                [mptcp.stream id]
        For now it is naive, does not look at retransmissions ?
                """
        print("arg=", mptcpstream)
        try:
            mptcpstream = int(mptcpstream)
        except ValueError as e:
            print("Expecting the mptcp.stream id as argument")
            return

        df = self.data[self.data.mptcpstream == mptcpstream]
        # for instance
        dsn_min = df.dss_dsn.min()
        dsn_max = df.dss_dsn.max()
        total_transferred = dsn_max - dsn_min
        d = df.groupby('tcpstream')
        # drop_duplicates(subset='rownum', take_last=True)
        print("mptcpstream %d transferred %d" %
              (mptcpstream, total_transferred))
        for tcpstream, group in d:
            subflow_load = group.drop_duplicates(
                subset="dss_dsn").dss_length.sum()
            print(subflow_load)
            print(subflow_load)
            print('tcpstream %d transferred %d out of %d, hence is responsible for %f%%' % (
                tcpstream, subflow_load, total_transferred, subflow_load / total_transferred * 100))

    def do_lc(self, *args):
        """ 
        List mptcp connections via their ids (mptcp.stream)
        """
        print('mptcp connections')
        self.data.describe()
        mp = self.data.groupby("mptcpstream")
        for mptcpstream, group in mp:
            self.do_ls(mptcpstream)

    def do_load(self, args):
        """
        Not implemented yet
        """
        print("Not implemented yet")
        # log.info("Preparing to convert %s into %s" %
                # (args.input, csv_filename))
        # exporter = TsharkExporter(cfg["DEFAULT"]["tshark_binary"], delimiter=delimiter)
        # retcode, stderr = exporter.export_to_csv(args.input, csv_filename)

    # def do_pdsn(self, args):
    def do_p(self, args):
        """
        Alias for plot
        """
        self.plot(args)

    def do_plot(self, args):
        """
        Plot DSN vs time
            [mptcp.stream]
        """
        self.plot_mptcpstream(args)

    def help_plot(self):
        print("Hello world")

    def complete_plot(self, text, line, begidx, endidx):
        # types = self._get_available_plots()
        # print("Line=%s" % line)
        # print("text=%s" % text)
        # print(types)
        l = [x for x in types if x.startswith(text)]
        # print(l)
        return l

    def plot_mptcpstream(self, args):
        """
        global member used by others do_plot members *
        """

        # plot_types = Plot.get_available_plots( '/home/teto/mptcpanalyzer/mptcpanalyzer/plots')
        # plot_subclasses = Plot.get_available_plots(
            # 'mptcpanalyzer/mptcpanalyzer/plots')
        # plot_types = dict((x.__name__, x) for x in plot_subclasses)
        # map(plot_types)

        # print(plot_types)
        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots')

        subparsers = parser.add_subparsers(
            dest="plot_type", title="Subparsers", help='sub-command help', )
        subparsers.required=True

        def _register_plots(ext, subparsers):
            subparsers.add_parser(ext.name, parents=[ext.obj.default_parser()], add_help=False)

        self.plot_mgr.map(_register_plots, subparsers)
        # results = mgr.map(_get_plot_names, "toto")
        # for name, subplot in plot_types.items():
            # subparsers.add_parser(
                # name, parents=[subplot.default_parser()], add_help=False)

        # parse
        # parser.add_argument('plot_type', action="store", choices=plot_types, help='Field to draw (see mptcp_fields.json)')
        # # parser.add_argument('mptcpstream', action="store", type=int, help='mptcp.stream id')
        # parser.add_argument('--out', action="store", nargs="?", default="output.png", help='Name of the output file')
        # parser.add_argument('--display', action="store_true", help='will display the generated plot')
        # # shlex.split(args) ?
        try:
            # args = parser.parse_args( shlex.split(field + ' ' + args))
            args, unknown = parser.parse_known_args(shlex.split(args))
        except SystemExit:
            return
        print(args)

        # instancier le bon puis appeler le plot dessus
        # mandatory_fields
        # newPlot = plot_types[args.plot_type]()
        # print(newPlot)
        # self.plot_mgr["dsn"].obj.plot()
        success = self.plot_mgr["dsn"].obj.plot(self.data, args)  # "toto")
        # success = newPlot.plot(self.data, args.out, unknown)
        # returns a DataFrame
        # os.path.realpath
        # lines, labels = ax1.get_legend_handles_labels()

        # cmd = "xdg-open %s" % (args.out,)
        # print(cmd)
        # if args.out and args.display:
            # os.system(cmd)

    def do_dump(self, args):
        """
        Dumps content of the csv file, with columns selected by the user
        """
        parser = argparse.ArgumentParser(description="dumps csv content")
        parser.add_argument('columns', default=[
                            "ipsrc", "ipdst"], choices=self.data.columns, nargs="*")
        args = parser.parse_args(shlex.split(args))
        print(self.data[args.columns])

    def complete_dump(self, text, line, begidx, endidx):
        """
        Should return a list of possibilities
        """
        # print("text=", text)
        l = [x for x in self.data.columns if x.startswith(text)]
        # print(l)
        return l

    def do_q(self, *args):
        """
        Quit/exit program
        """
        return True

    def do_EOF(self, line):
        """
        """
        return True

    def preloop(intro):
        print(intro)


# def generate_csv_from_pcap()

def cli():
    """
    return value will be passed to sys.exit
    """
    parser = argparse.ArgumentParser(
        description='Generate MPTCP stats & plots'
    )
    parser.add_argument("input", action="store",
                        help="Either a pcap or a csv file (in good format)."
                        "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
                        "If it can't find one (or with the flag --regen), it will generate a "
                        "csv from the pcap with the external tshark program."
                        )
    parser.add_argument("--config", "-c", action="store",
                        help="Path towards the config file (use $XDG_CONFIG_HOME/mptcpanalyzer/config by default)")
    parser.add_argument("--debug", "-d", action="store_true",
                        help="To output debug information")
    parser.add_argument("--regen", "-r", action="store_true",
                        help="Force the regeneration of the cached CSV file from the pcap input")
    parser.add_argument("--batch", "-b", action="store", type=str,
                        help="Accepts a filename as argument from which commands will be loaded."
                        "Commands follow the same syntax as in the interpreter"
                        )
    # parser.add_argument("--command", "-c", action="store", type=str, nargs="*", help="Accepts a filename as argument from which commands will be loaded")


    # TODO here one could use parse_known_args
    args, unknown_args = parser.parse_known_args(sys.argv[1:])
    cfg = MpTcpAnalyzerConfig(args.config)
    print("Config", cfg)

    print(os.getcwd())
    basename, ext = os.path.splitext(args.input)
    print("Basename=%s" % basename)
    csv_filename = args.input

    if ext == ".csv":
        pass
    else:
        print("%s format is not supported as is. Needs to be converted first" %
              (args.input))
        csv_filename = args.input + ".csv"  #  str(Filetype.csv.value)
        cache = os.path.isfile(csv_filename)
        if cache:
            log.info("A cache %s was found" % csv_filename)
        # if matching csv does not exist yet or if generation forced
        if not cache or args.regen:
            log.info("Preparing to convert %s into %s" %
                     (args.input, csv_filename))

            exporter = TsharkExporter(cfg["DEFAULT"]["tshark_binary"], delimiter=delimiter)
            retcode, stderr = exporter.export_to_csv(args.input, csv_filename)
            print("exporter exited with code=", retcode)
            if retcode:
                raise Exception(stderr)

    log.info(" %s " % (args.input))

    # if I load from
    input = None
    try:
        if args.batch:
            input = open(args.batch, 'rt')
        # stdin=input
        # Disable rawinput module use
        # use_rawinput = False

        # here I want to generate automatically the csv file
        analyzer = MpTcpAnalyzer(cfg, csv_filename, input)

        # if extra parameters passed via the cmd line, consider it is
        if not input and unknown_args:
            analyzer.onecmd(' '.join(unknown_args))
        else:
            analyzer.cmdloop()
    except Exception as e:
        print("An error happened :\n%s" % e)
        print("Displaying backtrace:\n")
        print(traceback.print_exc())
        return 1
    finally:
        input.close() if input else None
        return 0


if __name__ == '__main__':
    cli()
