#!/usr/bin/env python
# -*- coding: utf8
# PYTHON_ARGCOMPLETE_OK
# vim: set et fenc=utf-8 ff=unix sts=4 sw=4 ts=4 :

# Copyright 2015-2016 Université Pierre et Marie Curie
# author: Matthieu coudron , matthieu.coudron@lip6.fr

# TODO list
# -would like to draw a bar with the repartition of the data between the different subflows with sthg like
#  plot(kind='barh', stacked=True);
# explaing how argparse to shell completion works;
# http://dingevoninteresse.de/wpblog/?p=176
# https://travelingfrontiers.wordpress.com/2010/05/16/command-processing-argument-completion-in-python-cmd-module/
import sys
import argparse
import logging
import os
# import glob
from mptcpanalyzer.tshark import TsharkExporter, Filetype
from mptcpanalyzer.plot import Plot
from mptcpanalyzer.config import MpTcpAnalyzerConfig
import mptcpanalyzer.data as core
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

#  tshark -T fields -e _ws.col.Source -r /mnt/ntfs/pcaps/demo.pcap


def get_default_fields():
    """
    Mapping between short names easy to use as a column title (in a CSV file) 
    and the wireshark field name
    There are some specific fields that require to use -o instead, 
    see tshark -G column-formats

    CAREFUL: when setting the type to int, pandas will throw an error if there
    are still NAs in the column. Relying on float64 permits to overcome this.

ark.exe -r file.pcap -T fields -E header=y -e frame.number -e col.AbsTime -e col.DeltaTime -e col.Source -e col.Destination -e col.Protocol -e col.Length -e col.Info
"""
    return {
            "frame.number":        ("packetid",),
            # reestablish once format is changed (see options)
            # "time": "frame.time",
            "frame.time_relative":        "reltime",
            "frame.time_delta":        "time_delta",
            # "frame.time":        "abstime",
            "frame.time_epoch":        "abstime",
            # "ipsrc": "_ws.col.Source",
            # "ipdst": "_ws.col.Destination",
            "_ws.col.ipsrc" : "ipsrc",
            "_ws.col.ipdst" : "ipdst",
            # "_ws.col.AbsTime": "abstime2",
            # "_ws.col.DeltaTime": "deltatime",
            # "ip.src":        "ipsrc",
            # "ip.dst":        "ipdst",
            "tcp.stream":        ("tcpstream", np.int64),
            "mptcp.stream":        "mptcpstream",
            "tcp.srcport":        "sport",
            "tcp.dstport":        "dport",
            # rawvalue is tcp.window_size_value
            # tcp.window_size takes into account scaling factor !
            "tcp.window_size":        "rwnd",
            "tcp.options.mptcp.sendkey"        : "sendkey",
            "tcp.options.mptcp.recvkey"        : "recvkey",
            "tcp.options.mptcp.recvtok"        : "recvtok",
            "tcp.options.mptcp.datafin.flag":        "datafin",
            "tcp.options.mptcp.subtype":        ("subtype", np.float64),
            "tcp.flags":        "tcpflags",
            "tcp.options.mptcp.rawdataseqno":        "dss_dsn",
            "tcp.options.mptcp.rawdataack":        "dss_rawack",
            "tcp.options.mptcp.subflowseqno":        "dss_ssn",
            "tcp.options.mptcp.datalvllen":        "dss_length",
            "tcp.options.mptcp.addrid":        "addrid",
            "mptcp.master":        "master",
            # TODO add sthg related to mapping analysis ?
            "tcp.seq":        ("tcpseq", np.float64),
            "tcp.len":        ("tcplen", np.float64),
            "mptcp.dsn":        "dsn",
            "mptcp.rawdsn64":        "dsnraw64",
            "mptcp.ack":        "dack",
        }
    
# decorator
def is_loaded(f):
    def wrapped(self, *args):
        print("wrapped")
        if self.data is not None:
            print("self.data")
            print("args=%r" % args)
            return f(self, *args)
        # def toto(*args):
        else:   
            print("Please load a file first")
        # return lambda _: print("Please load a file first")
        return None
    return wrapped


""" CSV delimiter """
# TODO load from config
delimiter = '|'


from collections import namedtuple

MpTcpSubflow = namedtuple('Subflow', ['ipsrc', 'ipdst', 'sport', 'dport'])


# class MpTcpSubflow:
#     def __init__(self, ):
#         pass
#     def is_master():
#     def look_for_addrid():
#     def select_towards_host():

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
    config = None
    # pandas data
    data = None 

    def __init__(self, cfg: MpTcpAnalyzerConfig, stdin=sys.stdin): 
        """
        stdin 
        """
        # stdin ?
        self.prompt = "%s> " % "Ready"
        self.config = cfg

        ### LOAD PLOTS 
        ######################
# you can have list available plots under the namespace 
# https://pypi.python.org/pypi/entry_point_inspector

        # mgr = driver.DriverManager(
        # TODO move to a load_plot_plugins function
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
        if stdin != sys.stdin:
            self.use_rawinput = False
            self.prompt = ""
            self.intro = ""

        """
        The optional arguments stdin and stdout specify the input and output file objects that the Cmd instance or subclass instance will use for input and output. If not specified, they will default to sys.stdin and sys.stdout.
        """
        # stdin
        super().__init__(completekey='tab', stdin=stdin)
# , sep='|'
        # there seems to be several improvements a
        # possible to set type of columns with dtype={'b': object, 'c': np.float64}
        # one can choose the column to use as index index_col=
    def precmd(self, line):
        """
        """
        # return shlex.split(line)
        # default behavior
        return line 

    def postcmd(self, stop, line):
        """
        Override baseclass
        returning false will cause interpretation to continue
        """
        return stop

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
    @is_loaded
    def do_ls(self, args):
        """ list mptcp subflows 
                [mptcp.stream id]
        """
        print(args)

        parser = argparse.ArgumentParser(
                description="Display help"
                )
        # client = parser.add_argument_group("Client data")

        parser.add_argument("mptcpstream", action="store", type=int,
                help="Equivalent to mptcp.stream id" 
                )

        parser.add_argument("--json", action="store_true", 
                help="Return results but in json format"
                )
        # try:
        #     mptcpstream = int(mptcpstream)
        # except ValueError as e:
        #     print("Expecting the mptcp.stream id as argument")
        #     return
        
        args = parser.parse_args (shlex.split(args))
        mptcpstream = args.mptcpstream
        print('hello for mptcpstream %d' % mptcpstream )
        group = self.data[self.data.mptcpstream == args.mptcpstream]
        tcpstreams = group.groupby('tcpstream')
        self.data.head(5)
        print("mptcp.stream %d has %d subflow(s): " %
              (mptcpstream, len(tcpstreams)))
        for tcpstream, gr2 in tcpstreams:
            # print("gr2=", gr2.iloc[,'ipsrc'])
            # TODO look for master
            # and MP_JOIN   
            master = False
            
            # print(gr2.subtype)
            # print(gr2.addrid)
            extra = ""
            addrid = [] # (None,None,)
            if len(gr2[gr2.master == 1]) > 0:
                addrid = ["master", "master"]
            else:
                # look for MP_JOIN <=> tcp.options.mptcp.subtype == 1
                # la ca foire 
                for i, ipsrc in enumerate( [gr2['ipsrc'].iloc[0], gr2['ipdst'].iloc[0] ]):
                    gro= gr2[(gr2.tcpflags >= 2) & (gr2.addrid) & (gr2.ipsrc == ipsrc)]
                    # print("nb of results:", len(gro))
                    if len(gro):
                        # print("i=",i)
                        value = int(gro["addrid"].iloc[0])
                    else:
                        value = "Unknown"
                    addrid.insert(i, value)

            line = ("\ttcp.stream {tcpstream} : {srcip}:{sport} (addrid={addrid[0]})"
                    " <-> {dstip}:{dport} (addrid={addrid[1]})").format(
                    tcpstream=tcpstream,
                    srcip=gr2['ipsrc'].iloc[0],
                    sport=gr2['sport'].iloc[0], 
                    dstip=gr2['ipdst'].iloc[0], 
                    dport=gr2['dport'].iloc[0],
                    addrid=addrid,
                    # extra=extra
                    # addressid1="master" if master else 0
                    )
            print(line)

    def help_ls(self):

        return "Use parser -h"

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

    @is_loaded
    def do_lc(self, *args):
        """ 
        List mptcp connections via their ids (mptcp.stream)
        """
        print('mptcp connections')
        self.data.describe()
        mp = self.data.groupby("mptcpstream")
        for mptcpstream, group in mp:
            self.do_ls(mptcpstream)


    # def _print_subflow():


        # et ensuite tu fais reltime_x - reltime_y
        # to drop NA rows
        # s1.dropna(inplace=True)

    # @staticmethod
    def do_load(self, args):
        """
        """
        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots'
        )
        parser.add_argument("input_file", action="store", 
                #nargs="?",
                help="Either a pcap or a csv file (in good format)."
                "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
                "If it can't find one (or with the flag --regen), it will generate a "
                "csv from the pcap with the external tshark program."
                )
        parser.add_argument("--regen", "-r", action="store_true",
                help="Force the regeneration of the cached CSV file from the pcap input")

        args = parser.parse_args(shlex.split(args))

        # print("Not implemented yet")
        csv_filename = core.get_matching_csv_filename (args.input_file, args.regen)

        self.data = core.load_into_pandas(csv_filename)
        self.prompt = "%s> " % csv_filename



    # @staticmethod


    # def do_load_csv(self, args):
        # """
        # """
        # # TODO run some check on the pcap to check if column names match
        # print("Not implemented yet")
        # csv_filename = args 
        # print("Loading csv %s" % csv_filename)
        # self.data = self._load_into_pandas(csv_filename)

    # TODO add a do_multiplot ?
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


    def do_list_available_plots(self, args):
        
        plot_names = self._list_available_plots()
        print(names)

    def _list_available_plots(self):
        def _get_names(ext, names: list):
            names.append (ext.name) 
        
        names = []
        self.plot_mgr.map(_get_names, names)
        def _get_names(ext, names: list):
            names.append (ext.name) 
        
        names = []
        self.plot_mgr.map(_get_names, names)
        return names

    def plot_mptcpstream(self, args):
        """
        global member used by others do_plot members *
        """

        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots')

        # parser.add_argument('--out', action="store", default="output.png", help='Name of the output file')
        # parser.add_argument('--display', action="store_true", help='will display the generated plot')

        subparsers = parser.add_subparsers(
            dest="plot_type", title="Subparsers", help='sub-command help', )
        subparsers.required=True

        def _register_plots(ext, subparsers):
            subparsers.add_parser(ext.name, parents=[ext.obj.default_parser()], 
                    add_help=False
                    )

        self.plot_mgr.map(_register_plots, subparsers)

        # results = mgr.map(_get_plot_names, "toto")
        # for name, subplot in plot_types.items():
            # subparsers.add_parser(
                # name, parents=[subplot.default_parser()], add_help=False)

        try:
            # TODO passer les unknown
            args = shlex.split(args)
            args, unknown = parser.parse_known_args(args)
            print(args)
# TODO fix
            plotter = self.plot_mgr[args.plot_type].obj
            success = plotter.plot(self.data, args)

        except SystemExit as e:
            # e is the error code to call sys.exit() with
            print("Parser failure:", e)
        except NotImplementedError:
            print("Plot subclass miss a requested feature")
            return

        # instancier le bon puis appeler le plot dessus
        # mandatory_fields
        # newPlot = plot_types[args.plot_type]()
        # print(newPlot)
        # self.plot_mgr["dsn"].obj.plot()
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
        """
        Executed once when cmdloop is called
        """
        print(intro)



def cli():
    """
    return value will be passed to sys.exit
    """
    parser = argparse.ArgumentParser(
        description='Generate MPTCP stats & plots'
    )
    #  todo make it optional
    parser.add_argument("input_file", action="store", nargs="?",
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
    parser.add_argument("--batch", "-b", action="store", type=argparse.FileType('r'),
            default=sys.stdin,
            help="Accepts a filename as argument from which commands will be loaded."
            "Commands follow the same syntax as in the interpreter"
            )
    # parser.add_argument("--command", "-c", action="store", type=str, nargs="*", help="Accepts a filename as argument from which commands will be loaded")


    # TODO here one could use parse_known_args
    args, unknown_args = parser.parse_known_args(sys.argv[1:])
    cfg = MpTcpAnalyzerConfig(args.config)
    print("Config", cfg)
    # log.info(" %s " % (args.input_file))

    # if I load from
    input = None
    try:

        # if args.batch:
            # input = open(args.batch, 'rt')

        # stdin=input
        # Disable rawinput module use
        # use_rawinput = False

#         # here I want to generate automatically the csv file
#         # stdin = open(args.batch, 'rt') if args.batch else sys.stdin
        analyzer = MpTcpAnalyzer(cfg, )
#         # TODO convert that into load
        if args.input_file:
            analyzer.do_load(args.input_file + " " + "--regen" if str(args.regen) else "")
            # csv_filename = analyzer._get_matching_csv_filename(args.input_file, args.regen)
            # analyzer.do_load_csv(csv_filename)

        # if extra parameters passed via the cmd line, consider it is one command
        # not args.batch ? both should conflict
        if unknown_args:
            log.info("One-shot command: %s" % unknown_args)
            analyzer.onecmd(' '.join(unknown_args))
        else:
            log.info("Interactive mode")
            analyzer.cmdloop()

    except Exception as e:
        print("An error happened :\n%s" % e)
        print("Displaying backtrace:\n")
        print(traceback.print_exc())
        return 1
    finally:
        # input.close() if input else None
        return 0


if __name__ == '__main__':
    cli()
