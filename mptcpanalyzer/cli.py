#!/usr/bin/env python3
# -*- coding: utf8
# PYTHON_ARGCOMPLETE_OK
# vim: set et fenc=utf-8 ff=unix sts=4 sw=4 ts=4 :

# Copyright 2015-2016 Université Pierre et Marie Curie
# Copyright 2017 IIJ Initiative for Internet Japan
#
# Matthieu coudron , coudron@iij.ad.jp
"""
# the PYTHON_ARGCOMPLETE_OK line a few lines up can enable shell completion
for argparse scripts as explained in
- http://dingevoninteresse.de/wpblog/?p=176
- https://travelingfrontiers.wordpress.com/2010/05/16/command-processing-argument-completion-in-python-cmd-module/

todo test https://github.com/jonathanslenders/python-prompt-toolkit/tree/master/examples/tutorial
"""
import sys
import argparse
import logging
import os
import subprocess
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.tshark import TsharkConfig
from mptcpanalyzer.version import __version__
from mptcpanalyzer.data import mptcp_match_connection, load_into_pandas
# from mptcpanalyzer.cache import Cache, cache
from mptcpanalyzer.metadata import Metadata
from mptcpanalyzer.connection import MpTcpConnection
import mptcpanalyzer.cache as mc
import mptcpanalyzer.statistics as stats
import mptcpanalyzer as mp
import stevedore
import pandas as pd
import shlex
import traceback
import pprint
import textwrap
import readline
from typing import List, Any, Tuple, Dict, Callable, Set
# from cmd import Cmd
from cmd2 import Cmd

from stevedore import extension

plugin_logger = logging.getLogger("stevedore")
plugin_logger.addHandler(logging.StreamHandler())

log = logging.getLogger("mptcpanalyzer")
ch = logging.StreamHandler()
formatter = logging.Formatter('%(name)s:%(levelname)s: %(message)s')
ch.setFormatter(formatter)

log.addHandler(ch)
log.setLevel(logging.DEBUG)
# handler = logging.FileHandler("mptcpanalyzer.log", delay=False)

print("logger nqme from cli", __name__)

histfile_size = 100

def is_loaded(f):
    """
    Decorator checking that dataset has correct columns
    """
    def wrapped(self, *args):
        if self.data is not None:
            return f(self, *args)
        else:
            raise mp.MpTcpException("Please load a pcap with `load` first")
        return None
    return wrapped


class MpTcpAnalyzer(Cmd):
    """
    mptcpanalyzer can run into 3 modes:

    #. interactive mode (default): an interpreter with some basic completion will accept your commands.
    There is also some help embedded.
    #. if a filename is passed as argument, it will load commands from
    this file otherwise, it will consider the unknow arguments as one command,
     the same that could be used interactively
    """

    intro = textwrap.dedent("""
        Press ? to list the available commands and `help <command>` or `<command> -h`
        for a detailed help of the command
        """.format(__version__))

    def stevedore_error_handler(manager, entrypoint, exception):
        print("Error while loading entrypoint [%s]" % entrypoint)

    def __init__(self, cfg: MpTcpAnalyzerConfig, stdin=sys.stdin, **kwargs) -> None:
        """
        Args:
            cfg (MpTcpAnalyzerConfig): A valid configuration

        Attributes:
            prompt (str): Prompt seen by the user, displays currently loaded pcpa
            config: configution to get user parameters
            data:  dataframe currently in use
        """
        # self.colorize( , "blue")
        self.prompt = "%s> " % "Ready"
        self.data = None  # type: pd.DataFrame
        self.config = cfg
        self.tshark_config = TsharkConfig(
            cfg["mptcpanalyzer"]["tshark_binary"],
            cfg["mptcpanalyzer"]["delimiter"],
            cfg["mptcpanalyzer"]["wireshark_profile"],
        )

        # self.cache = Cache(self.config["cache"])
        # if kwargs.get('no_cache'):
        #     self.cache.disabled = True

        # cmd2 specific initialization
        self.abbrev = True;  #  when no ambiguities, run the command
        self.allow_cli_args = False;
        self.allow_redirection = True;  # allow pipes in commands
        self.default_to_shell = False;
        self.debug = True;  #  for now
        self.set_posix_shlex = True
        self.shortcuts.update({'lr': 'do_list_reinjections', '~': 'squirm'})

        # LOAD PLOTS
        ######################
        # you can  list available plots under the namespace
        # https://pypi.python.org/pypi/entry_point_inspector
        # stevedore doc has now moved to 
        # https://docs.openstack.org/stevedore/latest/reference/index.html#stevedore.extension.ExtensionManager
        # mgr = driver.DriverManager(
        self.plot_mgr = extension.ExtensionManager(
            namespace='mptcpanalyzer.plots',
            invoke_on_load=True,
            verify_requirements=True,
            invoke_args=(self.tshark_config,),
        )

        self.cmd_mgr = extension.ExtensionManager(
            namespace='mptcpanalyzer.cmds',
            invoke_on_load=True,
            verify_requirements=True,
            invoke_args=(),
            propagate_map_exceptions=False,
            on_load_failure_callback=self.stevedore_error_handler
        )

        # if loading commands from a file, we disable prompt not to pollute
        # output
        if stdin != sys.stdin:
            log.info("Disabling prompt because reading from stdin")
            self.use_rawinput = False
            self.prompt = ""
            self.intro = ""

        """
        The optional arguments stdin and stdout specify the input and
        output file objects that the Cmd instance or subclass instance will
        use for input and output. If not specified, they will default to
        sys.stdin and sys.stdout.
        """
        super().__init__(completekey='tab', stdin=stdin)

    @property
    def plot_manager(self):
        return self.plot_mgr

    @plot_manager.setter
    def plot_manager(self, mgr):
        """
        Override the default plot manager, only used for testing
        :param mgr: a stevedore plugin manager
        """
        self.plot_mgr = mgr

    # set_posix_shlex
    # def preparse(raw):
    #     return shlex.split(raw)

    def load_plugins(self, mgr=None):
        """
        This function monkey patches the class to inject Command plugins

        Attrs:
            mgr: override the default plugin manager when set.

        Useful to run tests
        """
        mgr = mgr if mgr is not None else self.cmd_mgr

        def _inject_cmd(ext, data):
            log.debug("Injecting plugin %s" % ext.name)
            for prefix in ["do", "help", "complete"]:
                method_name = prefix + "_" + ext.name
                try:
                    obj = getattr(ext.obj, prefix)
                    if obj:
                        setattr(MpTcpAnalyzer, method_name, obj)
                except AttributeError:
                    log.debug("Plugin does not provide %s" % method_name)

        # there is also map_method available
        try:
            mgr.map(_inject_cmd, self)
        except stevedore.exception.NoMatches as e:
            log.error("stevedore: No matches (%s)" % e)

    def precmd(self, line):
        """
        Here we can preprocess line, with for instance shlex.split() ?
        Note:
            This is only called when using cmdloop, not with onecmd !
        """
        # default behavior
        print(">>> %s" % line)
        return line

    def cmdloop(self, intro=None):
        """
        overrides baseclass just to be able to catch exceptions
        """
        try:
            super().cmdloop()
        except KeyboardInterrupt as e:
            pass

        # Exception raised by sys.exit(), which is called by argparse
        # we don't want the program to finish just when there is an input error
        except SystemExit as e:
            # e is the error code to call sys.exit() with
            # log.debug("Input error: " % e)
            # print("Error: %s"% e)
            self.cmdloop()
        # you can set a tuple of exceptions
        except mp.MpTcpException as e:
            print(e)
            self.cmdloop()
        except Exception as e:
            log.critical("Unknown error, aborting...")
            log.critical("%s" % e)
            print("Displaying backtrace:\n")
            traceback.print_exc()

        # finally:
        #     log.debug("Error logged")
        # except NotImplementedError:
        #     print("Plot subclass miss a requested feature")
        #     return 1

    def postcmd(self, stop, line):
        """
        Override baseclass
        returning true will stop the program
        """
        log.debug("postcmd result for line [%s] => %r", line, stop)

        return True if stop is True else False

    # def require_fields(mandatory_fields: list):  # -> Callable[...]:
    #     """
    #     Decorator used to check dataset contains all fields required by function
    #     """

    #     def check_fields(self, *args, **kwargs):
    #         columns = list(self.data.columns)
    #         for field in mandatory_fields:
    #             if field not in columns:
    #                 raise Exception(
    #                     "Missing mandatory field [%s] in csv, regen the file or check the separator" % field)
    #     return check_fields

    # @require_fields(['sport', 'dport', 'ipdst', 'ipsrc'])
    @is_loaded
    def do_list_subflows(self, args):
        """
        list mptcp subflows
                [mptcp.stream id]

        Example:
            ls 0
        """
        parser = argparse.ArgumentParser(
            description="List subflows of an MPTCP connection"
        )

        parser.add_argument(
            "mptcpstream", action="store", type=int,
            help="Equivalent to wireshark mptcp.stream id"
        )
        parser.add_argument(
            "-c", "--contributions", action="store_true", default=False,
            help="Display contribution of each subflow (taking into account reinjections ?)"
        )

        args = parser.parse_args(shlex.split(args))
        self.list_subflows(args.mptcpstream)

    @is_loaded
    def list_subflows(self, mptcpstreamid: int):
        con = MpTcpConnection.build_from_dataframe(self.data, mptcpstreamid)
        print("Description of mptcp.stream %d " % mptcpstreamid)
        print(con)

        print("The connection has %d subflow(s) (client/server): " % (len(con.subflows)))
        for sf in con.subflows:
            print("\t%s" % sf)

    def help_list_subflows(self):

        return "Use parser -h"

    def complete_list_subflows(self, text, line, begidx, endidx):
        """ help to complete the args """
        # conversion to set removes duplicate keys
        l = list(set(self.data["mptcpstream"]))
        # convert items to str else it won't be used for completion
        l = [str(x) for x in l]

        return l

    def do_map_connections(self, line):
        """
        Tries to map mptcp.streams from different pcaps.
        Score based mechanism

        Todo:
            - Limit number of displayed matches
        """
        parser = argparse.ArgumentParser(
            description="This function tries to map a mptcp.stream from a dataframe (aka pcap) to mptcp.stream"
                        "in another dataframe. ")

        parser.add_argument("pcap1", action="store", help="pcap1 to load")
        parser.add_argument("pcap2", action="store", help="")
        parser.add_argument("mptcpstreams", action="store", nargs="*", help="to filter")
        parser.add_argument(
            '-v', '--verbose', dest="verbose", default=False,
            action="store_true",
            help="how to display each connection")

        # parser.add_argument("--limit", dest="limit", type=int, action="store",
        #         help="by default process of choosing good values is interactive, this"
        #         "let the program automatically select the candidate with the best score")

        args = parser.parse_args(shlex.split(line))
        df1 = load_into_pandas(args.pcap1, self.tshark_config)
        df2 = load_into_pandas(args.pcap2, self.tshark_config)

        print("WORK IN PROGRESS, RESULTS MAY BE WRONG")
        print("Please read the help.")

        # TODO wrong api
        mappings = mptcp_match_connection(df1, df2, args.mptcpstreams)

        print("%d mapping(s) found" % len(mappings))

        for con1, scores in mappings.items():
            for con2, score in scores:

                output = "{c1.mptcpstreamid} <-> {c2.mptcpstreamid} with score={score}"
                if args.verbose:
                    output = "{c1.mptcpstreamid} <-> {c2.mptcpstreamid} with score={score}"
                formatted_output = output.format(
                    c1=con1,
                    c2=con2,
                    score=score
                )
                print(formatted_output)

    @is_loaded
    def do_summary(self, line):
        """
        Summarize contributions of each subflow
        For now it is naive, does not look at retransmissions ?
        """
        parser = argparse.ArgumentParser(
            description="Prints a summary of the mptcp connection"
        )
        parser.add_argument("mptcpstream", type=int, help="mptcp.stream id")
        # parser.add_argument("--deep", action="store_true", help="Deep analysis, computes transferred bytes etc...")
        # parser.add_argument("--amount", action="store_true", help="mptcp.stream id")

            # if direction:
            #     # a bit hackish: we want the object to be of type class
            #     # but we want to display the user readable version
            #     # so we subclass list to convert the Enum to str value first.
        # class CustomDestinationChoices(list):
        #     def __contains__(self, other):
        #         # print("%r", other)
        #         return super().__contains__(other.name)

        parser.add_argument(
                    'destination', 
                    action="store",
                    # type=lambda color: str(color) ,#; getattr(mp.Destination,x),
                    # choices=mp.Destination,
                    choices=mp.CustomDestinationChoices([e.name for e in mp.Destination]),
                    type=lambda x: mp.Destination[x],
                    # choices=[e.name.lower() for e in mp.Destination],
                    # type=lambda x: mp.Destination[x],
                    help='Filter flows according to their direction'
                    '(towards the client or the server)'
                    'Depends on mptcpstream')

        # try:
        #     mptcpstream = int(mptcpstream)
        # except ValueError as e:
        #     print("Expecting the mptcp.stream id as argument: %s" % e)
        #     return

        args = parser.parse_args(shlex.split(line))
        # args = parser.parse_args(line)
        # print("%s" % args)
        # TODO
        df = self.data
        mptcpstream = args.mptcpstream

        # con = MpTcpConnection.build_from_dataframe(df, mptcpstream)
        # q = con.generate_direction_query(destination)
        success, ret = stats.mptcp_compute_throughput(
                self.data, args.mptcpstream, args.destination
        )
        # df = self.data[self.data.mptcpstream == args.mptcpstream]
        # if df.empty:
        if success is not True:
            print("Throughput computation failed:")
            print(ret)
            return

        total_transferred = ret["total_bytes"]
        print("mptcpstream %d transferred %d" % (ret["mptcpstreamid"], ret["total_bytes"]))
        for tcpstream, sf_bytes in map(lambda sf: (sf["tcpstreamid"], sf["bytes"]), ret["subflow_stats"]):
            subflow_load = sf_bytes/ret["total_bytes"]
            # print(subflow_load)
            print('tcpstream %d transferred %d out of %d, accounting for %f%%' % (
                tcpstream, sf_bytes, total_transferred, subflow_load*100))

        # TODO check for reinjections etc...

    @is_loaded
    def do_lc(self, *args):
        """
        List mptcp connections via their ids (mptcp.stream)
        """
        # self.data.describe()
        streams = self.data.groupby("mptcpstream")

        print('%d mptcp connection(s)' % len(streams))
        for mptcpstream, group in streams:
            self.list_subflows(mptcpstream)

    # @is_loaded
    # def do_qualify_reinjections(self, line):
    #     """
    #     test with:
    #         mp qualify_reinjections 0
    #     """
    #     parser = argparse.ArgumentParser(
    #         description="Listing reinjections of the connection"
    #     )
    #     parser.add_argument("mptcpstream", type=int, help="mptcp.stream id")
    #     parser.add_argument("pcap1", type=str, help="Capture file 1")
    #     parser.add_argument("pcap2", type=str, help="Capture file 2")
    #     # TODO le rendre optionnel ?
    #     parser.add_argument("mptcpstream1", type=int, help="mptcp.stream id")
    #     # TODO filter on dest/role
    #     # parser.add_argument("--role", type=int, help="mptcp.stream id")
    #     # parser.add_argument("mptcpstream2", type=int, help="mptcp.stream id")

    #     args = parser.parse_known_args(line)

    #     raw_df1 = load_into_pandas(args.mptcpstream1)
    #     raw_df2 = load_into_pandas(args.mptcpstream2)

    #     df_merged = merge_mptcp_dataframes_known_streams(raw_df1, raw_df2, args.mptcpstream, args.mptcpstream1)
    #     """
    #     Maybe wisest approach is to merge only relevant informations and use packetid as Index in the original df ?


    #     Now the algorithm consists in :
    #     for each reinjection:
    #         look for the arrival time
    #             compare with the arrival time of the original packet
    #             if it arrived sooner:
    #                 than it's a successful reinjection
    #             else
    #                 look for the first emitted dataack on each packet reception
    #                 look for its reception by the sender
    #     """
    #     # df1 = raw_df1['tcpstream' == mptcpstream1]
    #     # 1/ keep list of original packets that are reinjected
    #     # i.e., "reinjected_in" not empty but reinjection_of empty
    #     # query = "mptcprole == '%s'" % (Destination.Client)
    #     # res = df_merged.query(query)
    #     # isnull / notnull
    #     # reinjections = df[["packetid", 'tcpstream', "reinjections"]].dropna(axis=0, )# subset="reinjections")

    #     # filter packets to only keep the original packets that are reinjected
    #     res2 = res[pd.isnull(res["reinjection_of"])]
    #     res2 = res2[pd.notnull(res["reinjected_in"])]
    #     print("filtering reinjected %d" % (len(res2)))

    @is_loaded
    def do_list_reinjections(self, line):
        """
        List reinjections
        We want to be able to distinguish between good and bad reinjections
        (like good and bad RTOs).
        A good reinjection is a reinjection for which either:
        - the segment arrives first at the receiver
        - the cumulative DACK arrives at the sender sooner thanks to that reinjection

        To do that, we need to take into account latencies

        """
        # mptcp.duplicated_dsn
        #
        print("Listing reinjections of the connection")
        parser = argparse.ArgumentParser(
            description="Listing reinjections of the connection"
        )
        parser.add_argument("mptcpstream", type=int, help="mptcp.stream id")
        args = parser.parse_args(line)
        df = self.data
        df = self.data[df.mptcpstream == args.mptcpstream]
        if df.empty:
            print("No packet with mptcp.stream == %d" % args.mptcpstream)
            return
        # type(reinjections) = list (assume it's sorted )
        # reinjections = df[["packetid", "reinjections"]]
        known : Set[int] = set()
        # reinjections = df["reinjections"].dropna()
        # subset="reinjections")
        reinjections = df[["packetid", 'tcpstream', "reinjections"]].dropna(axis=0, )
        total_nb_reinjections = 0
        # df.groupby('tcpstream')
        for row in reinjections.itertuples():
            # row.itertuples():
            if row.packetid not in known:
                print("packetid=%d reinjected in %s" % (row.packetid, row.reinjections))
                known.update([row.packetid] + row.reinjections)

    # def do_batch(self, line):
    #     print("Running batched commands")
    #     # with open(args.batch) as fd:

    # def batch(self, fd):
    #     log.info("Batched commands")
    #     for command in fd:
    #         log.info(">>> %s" % command)
    #         self.onecmd(command)

    def load(self, filename, regen: bool=False):

        self.data = load_into_pandas(filename, self.tshark_config, regen)
        self.prompt = "%s> " % os.path.basename(filename)

    def do_load_pcap(self, args):
        """
        Load the file as the current one
        """
        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots'
        )
        parser.add_argument(
            "input_file", action="store",
            help="Either a pcap or a csv file (in good format)."
            "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
            "If it can't find one (or with the flag --regen), it will generate a "
            "csv from the pcap with the external tshark program.")
        parser.add_argument(
            "--regen", "-r", action="store_true",
            help="Force the regeneration of the cached CSV file from the pcap input")

        args = parser.parse_args(shlex.split(args))
        self.load(args.input_file, args.regen)

    def do_plot(self, args, mgr=None):
        """
        Plot DSN vs time
        """
        self.plot_mptcpstream(args)

    def help_plot(self):
        print("Run plot -h")

    def complete_plot(self, text, line, begidx, endidx):
        types = self._get_available_plots()
        # print("Line=%s" % line)
        # print("text=%s" % text)
        # print(types)
        l = [x for x in types if x.startswith(text)]
        return l

    def do_list_available_plots(self, args):
        """
        Print available plots. Mostly for debug, you should use 'plot'.
        """
        plot_names = self.list_available_plots()
        print(plot_names)

    def list_available_plots(self):
        return self.plot_mgr.names()

    def pcap_loaded(self):
        return isinstance(self.data, pd.DataFrame)

    def plot_mptcpstream(self, cli_args, ):
        """
        global member used by others do_plot members *
        Loads required dataframes when necessary
        """

        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots')

        # TODO if no df loaded, add an argument ? or the plot should
        # say how many it needs?
        # if self.data is None:
        #     parser.add_argument()

        subparsers = parser.add_subparsers(
            dest="plot_type", title="Subparsers", help='sub-command help',)
        subparsers.required = True  # type: ignore

        def register_plots(ext, subparsers):
            """Adds a parser per plot"""
            # check if dat is loaded
            parser = ext.obj.default_parser()
            assert parser, "Forgot to return parser"
            subparsers.add_parser(
                ext.name, parents=[parser], add_help=False
            )

        self.plot_mgr.map(register_plots, subparsers)


        cli_args = shlex.split(cli_args)
        args, unknown_args = parser.parse_known_args(cli_args)
        # Allocate plot object
        # self.tshark_config
        plotter = self.plot_mgr[args.plot_type].obj

        # dataframes = []
        # if self.data is not None:
        #     dataframes.append(self.data)

        dargs = vars(args)  # 'converts' the namespace to a dict

        # TODO
        # print("TOTO")
        dataframes = plotter.preprocess(self, **dargs)
        # TODO test with isinstance ?
        assert dataframes is not None, "Preprocess must return a list"
        # print("dataframes", dataframes, " comapred to ", dargs)
        result = plotter.run(dataframes, **dargs)
        plotter.postprocess(result, **dargs)

        # except SystemExit as e:
        #     # e is the error code to call sys.exit() with
        #     print("Parser failure:", e)
        # except NotImplementedError:
        #     print("Plot subclass miss a requested feature")
        #     return 1

    def do_clean_cache(self, line):
        """
        mptcpanalyzer saves pcap to csv converted files in a cache folder, (most likely
        $XDG_CACHE_HOME/mptcpanalyzer). This commands clears the cache.
        """
        #
        cache =  mp.get_cache()
        print("Cleaning cache [%s]" % cache.folder)
        cache.clean()
        # for cached_csv in os.scandir(self.config.cache):
        #     log.info("Removing " + cached_csv.path)
        #     os.unlink(cached_csv.path)

    # def help_clean_cache(self):

    def do_dump(self, args):
        """
        Dumps content of the csv file, with columns selected by the user.
        Mostly used for debug
        """
        parser = argparse.ArgumentParser(description="dumps csv content")
        parser.add_argument('columns', default=[
                            "ipsrc", "ipdst"], choices=self.data.columns, nargs="*")

        parser.add_argument('-n', default=10, action="store",
                help="Number of results to display")
        args = parser.parse_args(shlex.split(args))
        print(self.data[args.columns])

    def complete_dump(self, text, line, begidx, endidx):
        """
        Should return a list of possibilities
        """
        l = [x for x in self.data.columns if x.startswith(text)]
        return l

    # not needed in cmd2
    # def do_quit(self, *args):
    #     """
    #     Quit/exit program
    #     """
    #     return True

    def do_EOF(self, line):
        """
        Keep it to be able to exit with CTRL+D
        """
        return True

    def preloop(self):
        """
        Executed once when cmdloop is called
        """
        # super().preloop()
        # print("toto")
        histfile = self.config["mptcpanalyzer"]['history']
        if readline and os.path.exists(histfile):
            readline.read_history_file(histfile)

    def postloop(self):
        histfile = self.config["mptcpanalyzer"]['history']
        if readline:
            readline.set_history_length(histfile_size)
            readline.write_history_file(histfile)

def main(arguments=None):
    """
    This is the entry point of the program

    Args:
        arguments_to_parse (list parsable by argparse.parse_args.): Made as a parameter since it makes testing easier


    Returns:
        return value will be passed to sys.exit
    """

    if not arguments:
        arguments = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description='Generate MPTCP (Multipath Transmission Control Protocol) stats & plots'
    )

    #  todo make it optional
    parser.add_argument(
        "--load", "-l", dest="input_file",
        # type=argparse
        # "input_file",  nargs="?",
        # action="store", default=None,
        help="Either a pcap or a csv file (in good format)."
        "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
        "If it can't find one (or with the flag --regen), it will generate a "
        "csv from the pcap with the external tshark program."
    )
    parser.add_argument('--version', action='version', version="%s" % (__version__))
    parser.add_argument(
        "--config", "-c", action="store",
        help="Path towards the config file. If not set, mptcpanalyzer will try"
        " to load first $XDG_CONFIG_HOME/mptcpanalyzer/config and then "
        " $HOME/.config/mptcpanalyzer/config"
    )
    parser.add_argument(
        "--debug", "-d", action="count", default=0,
        help="More verbose output, can be repeated to be even more "
        " verbose such as '-dddd'"
    )
    parser.add_argument(
        "--no-cache", "-r", action="store_true",
        default=False,
        help="mptcpanalyzer creates a cache of files in the folder "
        "$XDG_CACHE_HOME/mptcpanalyzer or ~/.config/mptcpanalyzer."
        "Force the regeneration of the cached CSV file from the pcap input"
    )
    parser.add_argument(
        "--cachedir", action="store",
        # default="$XDG_CACHE_HOME/mptcpanalyzer",
        type=str,
        # type=lambda x: os.path.isdir(x),
        help="mptcpanalyzer creates a cache of files in the folder "
        "$XDG_CACHE_HOME/mptcpanalyzer or ~/.config/mptcpanalyzer."
        "Force the regeneration of the cached CSV file from the pcap input"
    )


    # parser.add_argument(
    #     "--batch", "-b", action="store", type=argparse.FileType('r'),
    #     default=None,
    #     help="Accepts a filename as argument from which commands will be loaded."
    #     "Commands follow the same syntax as in the interpreter"
    #     "can also be used as "
    # )

    args, unknown_args = parser.parse_known_args(arguments)

    config = MpTcpAnalyzerConfig(args.config)
    if args.cachedir:
        config["mptcpanalyzer"]["cache"] = args.cachedir # type: ignore
    mp.__CACHE__ = mc.Cache(config.cachedir)

    if __name__ == '__main__':
        level = logging.CRITICAL - min(args.debug, 4) * 10
        # log.setLevel(level)
        print("Log level set to %s " % logging.getLevelName(level))

    log.info("Starting in folder %s" % os.getcwd())
    log.debug("Pandas version: %s" % pd.__version__)

    try:

        analyzer = MpTcpAnalyzer(config, **vars(args))

        if args.input_file:
            log.info("Input file")
            cmd = args.input_file
            # cmd += " -r" if args.regen else ""
            analyzer.do_load(cmd)
            # analyzer.onecmd(cmd)

        # if args.batch:
        #     log.info("Batched commands")
        #     analyzer.batch(args.batch)
            # # with open(args.batch) as fd:
            # for command in args.batch:
            #     log.info(">>> %s" % command)
            #     analyzer.onecmd(command)

        # if extra parameters passed via the cmd line, consider it is one command
        # not args.batch ? both should conflict
        elif unknown_args:
            log.info("One-shot command with unknown_args=  %s" % unknown_args)

            # list2cmdline is undocumented function so it  might disappear
            # http://stackoverflow.com/questions/12130163/how-to-get-resulting-subprocess-command-string
            # but just doing "analyzer.onecmd(' '.join(unknown_args))" is not enough
            cmd = subprocess.list2cmdline(unknown_args)  # type: ignore
            analyzer.onecmd(cmd)
        else:
            log.info("Starting interactive mode")
            analyzer.cmdloop()

    except Exception as e:
        print("An error happened :\n%s" % e)
        print("Displaying backtrace:\n")
        traceback.print_exc()
        return 1
    finally:
        return 0


if __name__ == '__main__':
    main()
