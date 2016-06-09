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
import subprocess
# import glob
from mptcpanalyzer.plot import Plot
from mptcpanalyzer.tshark import TsharkExporter, Filetype
from mptcpanalyzer.config import MpTcpAnalyzerConfig
# from mptcpanalyzer import get_default_fields, __default_fields__
from mptcpanalyzer.version import __version__
import mptcpanalyzer as mp
import stevedore
# import mptcpanalyzer.config
# import config
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import shlex
import cmd
import traceback
import pprint # for prettyprint

from stevedore import extension

log = logging.getLogger("stevedore")
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())

# "mptcpanalyzer"
log = logging.getLogger("mptcpanalyzer")
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())


print ( "log ", __name__)

# subparsers that need an mptcp_stream should inherit this parser
stream_parser = argparse.ArgumentParser(
    description='',
    # else conflicts with
    add_help=False
)

stream_parser.add_argument(
    "mptcp_stream", action="store", type=int, help="identifier of the MPTCP stream")



    
def is_loaded(f):
    """
    Decorator checking that dataset has correct columns
    """
    def wrapped(self, *args):
        print("wrapped")
        if self.data is not None:
            print("self.data")
            print("args=%r" % args)
            return f(self, *args)
        else:   
            print("Please load a file first")
        return None
    return wrapped






# class MpTcpSubflow:
#     def __init__(self, ):
#         pass
#     def is_master():
#     def look_for_addrid():
#     def select_towards_host():

class MpTcpAnalyzer(cmd.Cmd):
    # TODO print version
    intro = """
        Welcome in mptcpanalyzer (http://github.com/lip6-mptcp/mptcpanalyzer)
        Press ? to get help
        """
    # ruler = "="
    def stevedore_error_handler(manager, entrypoint, exception):
        print ("Error while loading entrypoint %s" % entrypoint)

    def __init__(self, cfg: MpTcpAnalyzerConfig, stdin=sys.stdin): 
        """
        stdin 
        """
        # stdin ?
        self.prompt = "%s> " % "Ready"
        self.config = cfg
        self.data = None

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
            propagate_map_exceptions=False,
            on_load_failure_callback=self.stevedore_error_handler
            )
        # TODO we should catch stevedore.exception.NoMatches
        
        def _inject_cmd(ext, data):
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

        # there is also map_method available
        try:
            results = self.cmd_mgr.map(_inject_cmd, self)
        except stevedore.exception.NoMatches as e:
            print("No matches")

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
        self._list_subflows(args.mptcpstream)

    @is_loaded
    def _list_subflows(self, mptcpstream : int):
        group = self.data[self.data.mptcpstream == mptcpstream]
        tcpstreams = group.groupby('tcpstream')
        self.data.head(5)
        print("mptcp.stream %d has %d subflow(s): " %
              (mptcpstream, len(tcpstreams)))
        for tcpstream, gr2 in tcpstreams:
            # and MP_JOIN   
            master = False
            
            extra = ""
            addrid = [] 
            if len(gr2[gr2.master == 1]) > 0:
                addrid = ["master", "master"]
            else:
                # look for MP_JOIN <=> tcp.options.mptcp.subtype == 1
                # la ca foire 
                for i, ipsrc in enumerate( [gr2['ipsrc'].iloc[0], gr2['ipdst'].iloc[0] ]):
                    gro=gr2[(gr2.tcpflags >= 2) & (gr2.addrid) & (gr2.ipsrc == ipsrc)]
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
        streams = self.data.groupby("mptcpstream")
        for mptcpstream, group in streams:
            self._list_subflows(mptcpstream)


    def _load_data(self, filename, regen: bool =False):
        """
        Register into self.data a panda dataframe loaded from filename: a csv file either
        from a previous 
        """
        # csv_filename = self.get_matching_csv_filename (args.input_file, args.regen)

        self.data = self.load_into_pandas(filename, regen)

        # os.path.basename()
        self.prompt = "%s> " % os.path.basename(filename)

    def do_load(self, args):
        """
        """
        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots'
        )
        parser.add_argument("input_file", action="store", 
                help="Either a pcap or a csv file (in good format)."
                "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
                "If it can't find one (or with the flag --regen), it will generate a "
                "csv from the pcap with the external tshark program."
                )
        parser.add_argument("--regen", "-r", action="store_true",
                help="Force the regeneration of the cached CSV file from the pcap input")

        args = parser.parse_args(shlex.split(args))

        return self._load_data(args.input_file, args.regen)

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
        print(plot_names)

    def _list_available_plots(self):
        def _get_names(ext, names: list):
            names.append (ext.name) 
        
        names = []
        # self.plot_mgr.map(_get_names, names)
        # def _get_names(ext, names: list):
        #     names.append (ext.name) 
        
        # self.plot_mgr.map(_get_names, names)
        # return names
        return self.plot_mgr.names()

# TODO rename look intocache ?
    def get_matching_csv_filename(self, filename, force_regen : bool):
        """
        Expects a realpath as filename
        Accept either a .csv or a .pcap file 
        Returns realpath towards resulting csv filename
        """
        realpath = filename
        basename, ext = os.path.splitext(realpath)
        print("Basename=%s" % basename)
        # csv_filename = filename

        if ext == ".csv":
            log.debug("Filename already has a .csv extension")
            csv_filename = realpath
        else:
            print("%s format is not supported as is. Needs to be converted first" %
                (filename))

            def matching_cache_filename(filename):
                """
                Expects a realpath else
                """
                # create a list of path elements (separated by system separator '/' or '\'
                # from the absolute filename
                l = os.path.realpath(filename).split(os.path.sep)
                res = os.path.join(self.config["DEFAULT"]["cache"], '%'.join(l))
                print(res)
                _, ext = os.path.splitext(filename)
                if ext != ".csv":
                    res += ".csv"
                return res

            # csv_filename = filename + ".csv"  #  str(Filetype.csv.value)
            csv_filename = matching_cache_filename(realpath)
            cache_is_invalid = True
            
            print("Checking for %s" % csv_filename)
            if os.path.isfile(csv_filename):
                log.info("A cache %s was found" % csv_filename)
                ctime_cached = os.path.getctime(csv_filename)
                ctime_pcap = os.path.getctime(filename)
                # print(ctime_cached , " vs ", ctime_pcap)

                if ctime_cached > ctime_pcap:
                    log.debug("Cache seems valid")
                    cache_is_invalid = False
                else:
                    log.debug("Cache seems outdated")


            # if matching csv does not exist yet or if generation forced
            if force_regen or cache_is_invalid:
                log.info("Preparing to convert %s into %s" %
                        (filename, csv_filename))

                exporter = TsharkExporter(
                        self.config["DEFAULT"]["tshark_binary"], 
                        self.config["DEFAULT"]["delimiter"], 
                        self.config["DEFAULT"]["wireshark_profile"], 
                )

                retcode, stderr = exporter.export_to_csv(
                        filename,
                        csv_filename, 
                        mp.get_fields("fullname", "name"),
                        tshark_filter="mptcp and not icmp"
                )
                print("exporter exited with code=", retcode)
                if retcode:
                    raise Exception(stderr)
        return csv_filename

    def load_into_pandas(self, input_file, regen : bool =False):
        """
        intput_file can be filename or fd
        load csv mptpcp data into panda
        """
        # exporter
        log.debug("Asked to load %s" % input_file)
        pp = pprint.PrettyPrinter(indent=4)

        filename = os.path.expanduser(input_file)
        filename = os.path.realpath(filename)
        csv_filename = self.get_matching_csv_filename(filename, regen)

        # dtypes = mp.get_fields("fullname", "type")
        temp = mp.get_fields("fullname", "type")
        # print(temp)
        dtypes = { k:v for k,v in temp.items() if v is not None}
        # TODO use dtype parameters to enforce a type
        log.debug ("Loading a csv file %s" % csv_filename)

        pp.pprint(dtypes)
        #converters
            # log.debug("dtypes before loading: %s\n" % )
        data = pd.read_csv(csv_filename, sep=self.config["DEFAULT"]["delimiter"],
                dtype=dtypes,
                # parse the following columns as date/time
                # in fact it is not a datetime, just plain nanoseconds
                # parse_dates=[
                #     "frame.time_relative",
# #                    "frame.time_epoch", # for now we don't care about epoch
                #     ],
                # # Here we specify a format, can we do it on a per column basis ?
                # date_parser=lambda x: pd.datetime.strptime(x,),
                converters={
                    "tcp.flags":lambda x: int(x,16),
                    # "frame.abs"
                    }
                ) 
        # data = pd.read_csv(csv_filename, sep=delimiter, engine="c", dtype=dtypes)


        data.rename (inplace=True, columns=mp.get_fields("fullname", "name"))

        # data.tcpseq = data.apply(pd.to_numeric, errors='coerce')
        # convert from hexa to numeric
        # print(data.dtypes)
        # data.tcpflags = data.tcpflags.apply( )

        # columns = list(data.columns)
        # print("==> column names:", columns)
        log.debug("Dtypes after load:%s\n" % pp.pprint(data.dtypes))
        return data

    def plot_mptcpstream(self, args):
        """
        global member used by others do_plot members *
        """

        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots')

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

            # log.debug("before shlex magic ", args)
            args = shlex.split(args)
            # log.debug("before parsing %s"% args)
            args, unknown = parser.parse_known_args(args)
            # log.debug("args=", args)
            # log.debug("unknown="% unknown)
            plotter = self.plot_mgr[args.plot_type].obj
            success = plotter.plot(self, args)

        except SystemExit as e:
            # e is the error code to call sys.exit() with
            print("Parser failure:", e)
        except NotImplementedError:
            print("Plot subclass miss a requested feature")
            return

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
    parser.add_argument(
            "--load","-l", dest="input_file", 
            # type=argparse
            # "input_file",  nargs="?", 
            # action="store", default=None,
            help="Either a pcap or a csv file (in good format)."
            "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
            "If it can't find one (or with the flag --regen), it will generate a "
            "csv from the pcap with the external tshark program."
            )
    parser.add_argument('--version', action='version', version="%s" % (__version__))
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

    # if I load from todo rename
    # input = None
    try:

        # if args.batch:
            # input = open(args.batch, 'rt')
        print("input=", args.input_file)
        print("unknown=", unknown_args)

        # stdin=input
        # Disable rawinput module use
        # use_rawinput = False

#         # here I want to generate automatically the csv file
#         # stdin = open(args.batch, 'rt') if args.batch else sys.stdin
        analyzer = MpTcpAnalyzer(cfg, )
#         # TODO convert that into load
        if args.input_file:
            analyzer._load_data (args.input_file, args.regen)

        # if extra parameters passed via the cmd line, consider it is one command
        # not args.batch ? both should conflict
        if unknown_args:
            log.info("One-shot command with unknown_args=  %s" % unknown_args)

            # undocumented function so it  might disappear 
            # http://stackoverflow.com/questions/12130163/how-to-get-resulting-subprocess-command-string
            # but just doing "analyzer.onecmd(' '.join(unknown_args))" is not enough
            analyzer.onecmd(subprocess.list2cmdline(unknown_args))
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
