# -*- coding: utf8
# PYTHON_ARGCOMPLETE_OK
# vim: set et fenc=utf-8 ff=unix sts=4 sw=4 ts=4 :

# Copyright 2015-2016 Université Pierre et Marie Curie
# Copyright 2017 IIJ Initiative for Internet Japan
#
# Matthieu coudron, coudron@iij.ad.jp
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
import functools
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.tshark import TsharkConfig
from mptcpanalyzer.version import __version__
import mptcpanalyzer.data as mpdata
from mptcpanalyzer.data import map_mptcp_connection, load_into_pandas, map_tcp_stream, merge_mptcp_dataframes_known_streams, merge_tcp_dataframes_known_streams, load_merged_streams_into_pandas, classify_reinjections, pandas_to_csv
from mptcpanalyzer import RECEIVER_SUFFIX, SENDER_SUFFIX, _sender, _receiver
from mptcpanalyzer.metadata import Metadata
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection, MpTcpMapping, TcpMapping, ConnectionRoles, swap_role
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
import numpy as np
from typing import List, Any, Tuple, Dict, Callable, Set
import cmd2
import math
from cmd2 import with_argparser, with_argparser_and_unknown_args, with_category, argparse_completer
from enum import Enum, auto


from stevedore import extension

plugin_logger = logging.getLogger("stevedore")
plugin_logger.addHandler(logging.StreamHandler())

log = logging.getLogger("mptcpanalyzer")
ch = logging.StreamHandler()
formatter = logging.Formatter('%(name)s:%(levelname)s: %(message)s')
ch.setFormatter(formatter)

log.addHandler(ch)
# log.setLevel(logging.DEBUG)
# handler = logging.FileHandler("mptcpanalyzer.log", delay=False)


histfile_size = 1000


# workaround to get
DestinationChoice = mp.CustomConnectionRolesChoices([e.name for e in mp.ConnectionRoles])


CAT_TCP = "TCP related"
CAT_MPTCP = "MPTCP related"
CAT_GENERAL = "Tool"

def is_loaded(f):
    """
    Decorator checking that dataset has correct columns
    """
    def wrapped(self, *args):
        if self.data is not None:
            return f(self, *args)
        else:
            raise mp.MpTcpException("Please load a pcap with `load_pcap` first")
        return None
    return wrapped




def experimental(f):
    """
    Decorator checking that dataset has correct columns
    """
    # @functools.wraps(f)
    def wrapped(self, *args, **kwargs):
        print("WORK IN PROGRESS, RESULTS MAY BE WRONG")
        return f(self, *args, **kwargs)
    return wrapped


def gen_bicap_parser(protocol, dest=False):
    """
    protocol in ["mptcp", "tcp"]
    """
    parser = argparse_completer.ACArgumentParser(
        description="""
        Empty description, please provide one
        """
    )
    parser.add_argument("pcap1", type=str, help="Capture file 1")
    parser.add_argument("pcap2", type=str, help="Capture file 2")
    parser.add_argument(protocol + "stream", type=int, help=protocol + ".stream wireshark id")
    parser.add_argument(protocol + "stream2", type=int, help=protocol + "stream wireshark id")

    if dest:
        dest_action = parser.add_argument(
            '--destination',
            action="store",
            choices=DestinationChoice,
            type=lambda x: mp.ConnectionRoles[x],
            # default=[ mp.ConnectionRoles.Server, mp.ConnectionRoles.Client ],
            help='Filter flows according to their direction'
            '(towards the client or the server)'
            'Depends on mptcpstream'
        )

        # tag the action objects with completion providers. This can be a collection or a callable
        # setattr(dest_action, argparse_completer.ACTION_ARG_CHOICES, static_list_directors)
    return parser


class MpTcpAnalyzerCmdApp(cmd2.Cmd):
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

        self.shortcuts.update({
            'lc': 'list_connections',
            'ls': 'list_subflows',
            'lr': 'list_reinjections'
        })
        super().__init__(completekey='tab', stdin=stdin)
        self.prompt = self.colorize("Ready>" , "blue")
        self.data = None  # type: pd.DataFrame
        self.config = cfg
        self.tshark_config = TsharkConfig(
            cfg["mptcpanalyzer"]["tshark_binary"],
            cfg["mptcpanalyzer"]["delimiter"],
            cfg["mptcpanalyzer"]["wireshark_profile"],
        )

        # cmd2 specific initialization
        self.abbrev = True;  #  when no ambiguities, run the command
        self.allow_cli_args = True;  # disable autoload of transcripts
        self.allow_redirection = True;  # allow pipes in commands
        self.default_to_shell = False;
        self.debug = True;  #  for now
        self.set_posix_shlex = True  # need cmd2 >= 0.8

        # LOAD PLOTS
        ######################
        # you can  list available plots under the namespace
        # https://pypi.python.org/pypi/entry_point_inspector
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
        print("WARNING: mptcpanalyzer may require a custom wireshark. "
                "Check github for mptcp patches streaming.")


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
                        setattr(MpTcpAnalyzerCmdApp, method_name, obj)
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
            self.cmdloop()
        except mp.MpTcpException as e:
            print(e)
            self.cmdloop()
        except Exception as e:
            log.critical("Unknown error, aborting...")
            log.critical("%s" % e)
            print("Displaying backtrace:\n")
            traceback.print_exc()

    def postcmd(self, stop, line):
        """
        Override baseclass
        returning true will stop the program
        """
        log.debug("postcmd result for line [%s] => %r", line, stop)

        return True if stop is True else False


    parser = argparse_completer.ACArgumentParser(description="List subflows of an MPTCP connection")
    filter_stream = parser.add_argument("mptcpstream", action="store", type=int,
        help="Equivalent to wireshark mptcp.stream id")
    setattr(filter_stream, argparse_completer.ACTION_ARG_CHOICES, [0, 1, 2])
    parser.add_argument("-c", "--contributions", action="store_true", default=False,
        help="Display contribution of each subflow (taking into account reinjections ?)")

    @with_argparser(parser)
    @with_category(CAT_MPTCP)
    @is_loaded
    def do_list_subflows(self, args):
        """
        list mptcp subflows
                [mptcp.stream id]

        Example:
            ls 0
        """
        # args = parser.parse_args(shlex.split(args))
        self.list_subflows(args.mptcpstream)

    @is_loaded
    def list_subflows(self, mptcpstreamid: int):

        try:
            con = MpTcpConnection.build_from_dataframe(self.data, mptcpstreamid)
            self.poutput("Description of mptcp.stream %d " % mptcpstreamid)

            self.poutput("The connection has %d subflow(s) (client/server): " % (len(con.subflows())))
            for sf in con.subflows():
                self.poutput("\t%s" % sf)
        except mp.MpTcpException as e:
            self.poutput(e)

    # def help_list_subflows(self):
    #     print("Use parser -h")

    # def complete_list_subflows(self, text, line, begidx, endidx):
    #     """ help to complete the args """
    #     # conversion to set removes duplicate keys
    #     l = list(set(self.data["mptcpstream"]))
    #     # convert items to str else it won't be used for completion
    #     l = [str(x) for x in l]

    #     return l

    parser = argparse_completer.ACArgumentParser(
        description="This function tries to map a tcp.stream id from one pcap"
                    " to one in another pcap"
                    "in another dataframe. "
    )

    # todo should accept filetype of argparse.Filetype
    load_pcap1 = parser.add_argument("pcap1", action="store", help="first to load")
    load_pcap2 = parser.add_argument("pcap2", action="store", help="second pcap")

    # cmd2.Cmd.path_complete ?
    # setattr(action_stream, argparse_completer.ACTION_ARG_CHOICES, range(0, 10))
    setattr(load_pcap1, argparse_completer.ACTION_ARG_CHOICES, ('path_complete', [False, False]))
    setattr(load_pcap2, argparse_completer.ACTION_ARG_CHOICES, ('path_complete', [False, False]))

    parser.add_argument("tcpstreamid", action="store", type=int, help="tcp.stream id visible in wireshark")
    parser.add_argument( '-v', '--verbose', dest="verbose", default=False, action="store_true",
        help="how to display each connection")

    @with_argparser(parser)
    @with_category(CAT_TCP)
    def do_map_tcp_connection(self, args):

        # args = parser.parse_args(shlex.split(line))
        df1 = load_into_pandas(args.pcap1, self.tshark_config)
        df2 = load_into_pandas(args.pcap2, self.tshark_config)

        main_connection = TcpConnection.build_from_dataframe(df1, args.tcpstreamid)

        mappings = map_tcp_stream(df2, main_connection)

        self.poutput("%d mapping(s) found" % len(mappings))

        for match in mappings:

            # formatted_output = main.format_mapping(match)
            # output = "{c1.tcpstreamid} <-> {c2.tcpstreamid} with score={score}"
            # formatted_output = output.format(
            #     c1=main_connection,
            #     c2=match,
            #     score=score
            # )
            # print(formatted_output)
            self.poutput(match)


    parser = argparse.ArgumentParser(
        description="This function tries to map a mptcp.stream from a dataframe"
                    "(aka pcap) to mptcp.stream"
                    "in another dataframe. "
    )

    load_pcap1 = parser.add_argument("pcap1", action="store", type=str, help="first to load")
    load_pcap2 = parser.add_argument("pcap2", action="store", type=str, help="second pcap")

    setattr(load_pcap1, argparse_completer.ACTION_ARG_CHOICES, ('path_complete', [False, False]))
    setattr(load_pcap2, argparse_completer.ACTION_ARG_CHOICES, ('path_complete', [False, False]))
    parser.add_argument("mptcpstreamid", action="store", type=int, help="to filter")
    parser.add_argument("--trim", action="store", type=float, default=0, 
            help="Remove mappings with a score below this threshold")
    parser.add_argument("--limit", action="store", type=int, default=2,
            help="Limit display to the --limit best mappings")
    parser.add_argument( '-v', '--verbose', dest="verbose", default=False, action="store_true",
        help="display all candidates")

    @with_argparser(parser)
    @with_category(CAT_MPTCP)
    @experimental
    def do_map_mptcp_connection(self, args):
        """
        Tries to map mptcp.streams from different pcaps.
        Score based mechanism

        Todo:
            - Limit number of displayed matches
        """

        df1 = load_into_pandas(args.pcap1, self.tshark_config)
        df2 = load_into_pandas(args.pcap2, self.tshark_config)


        main_connection = MpTcpConnection.build_from_dataframe(df1, args.mptcpstreamid)
        mappings = map_mptcp_connection(df2, main_connection)


        self.poutput("%d mapping(s) found" % len(mappings))
        mappings.sort(key=lambda x: x.score, reverse=True)

        for rank, match in enumerate(mappings):

            if rank >= args.limit:
                self.pfeedback("ignoring mappings left")
                break

            winner_like = match.score == float('inf')

            output = "{c1.mptcpstreamid} <-> {c2.mptcpstreamid} with score={score} {extra}"
            formatted_output = output.format(
                c1=main_connection,
                c2=match.mapped,
                score=self.colorize(str(match.score), "red"),
                extra= " <-- should be a correct match" if winner_like else ""
            )

            if match.score < args.trim:
                continue

            # match = MpTcpMapping(match.mapped, match.score, mapped_subflows)
            def _print_subflow(x):
                return "\n-" + x[0].format_mapping(x[1])
                
            
            formatted_output += ''.join( [ _print_subflow(x) for x in match.subflow_mappings])

            self.poutput(formatted_output)


    parser = argparse.ArgumentParser(description="Prints a summary of the mptcp connection")
    action_stream = parser.add_argument("mptcpstream", type=int, help="mptcp.stream id")
    # self.data.mptcpstream.max()))
    setattr(action_stream, argparse_completer.ACTION_ARG_CHOICES, range(0, 10))

    parser.add_argument(
        'destination',
        action="store",
        choices=DestinationChoice,
        type=lambda x: mp.ConnectionRoles[x],
        help='Filter flows according to their direction'
        '(towards the client or the server)'
        'Depends on mptcpstream'
    )
    @with_argparser(parser)
    @is_loaded
    def do_summary(self, args):
        """
        Naive summary contributions of the mptcp connection
        See summary_extended for more details
        """

        df = self.data
        mptcpstream = args.mptcpstream

        success, ret = stats.mptcp_compute_throughput(
                self.data, args.mptcpstream, args.destination
        )
        if success is not True:
            print("Throughput computation failed:")
            print(ret)
            return

        mptcp_transferred = ret["mptcp_bytes"]
        self.poutput("mptcpstream %d transferred %d" % (ret["mptcpstreamid"], ret["mptcp_bytes"]))
        for tcpstream, sf_bytes in map(lambda sf: (sf["tcpstreamid"], sf["bytes"]), ret["subflow_stats"]):
            subflow_load = sf_bytes/ret["mptcp_bytes"]
            self.poutput('tcpstream %d transferred %d out of %d, accounting for %f%%' % (
                tcpstream, sf_bytes, mptcp_transferred, subflow_load*100))


    # TODO check for reinjections etc...
    parser = argparse_completer.ACArgumentParser(description="Export connection(s) to CSV")
    parser.add_argument("output", action="store", help="Output filename")
    # parser.add_argument("--stream", action="store", )
    # )

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--tcpstream', action='store', type=int)
    group.add_argument('--mptcpstream', action='store', type=int)
    # parser.add_argument("protocol", action="store", choices=["mptcp", "tcp"], help="tcp.stream id visible in wireshark")
    parser.add_argument("--destination", action="store", choices=DestinationChoice,
        help="tcp.stream id visible in wireshark")
    parser.add_argument("--drop-syn", action="store_true", default=False,
        help="Helper just for my very own specific usecase")
    @is_loaded
    @with_argparser(parser)
    def do_tocsv(self, args):
        """
        Selects tcp/mptcp/udp connection and exports it to csv
        """

        df = self.data
        if args.tcpstream:
            # df = df[ df.tcpstream == args.tcpstream]

            self.poutput("Filtering tcpstream")
            con = TcpConnection.build_from_dataframe(df, args.tcpstream)
            if args.destination:
                self.poutput("Filtering destination")
                q = con.generate_direction_query(args.destination)
                df = df.query(q)

        elif args.mptcpstream:
            self.poutput("Unsupported yet")
            # df = df[ df.mptcpstream == args.mptcpstream]


        # need to compute the destinations before dropping syn from the dataframe
        # df['tcpdest'] = np.nan;
        for streamid, subdf in df.groupby("tcpstream"):
            con = TcpConnection.build_from_dataframe(df, streamid)
            df = mpdata.tcpdest_from_connections(df, con)

            if args.drop_syn:
                # use subdf ?
                self.poutput("drop-syn Unsupported yet")
                df.drop(subdf.head(3).index, inplace=True)
                # drop 3 first packets of each connection ?
                # this should be a filter
                syns = df[df.tcpflags == mp.TcpFlags.SYN]
        #     df = df[ df.flags ]
        # if args.destination:
        #     if args.tcpstream:
                # TODO we should filter destination
                # df.
        self.poutput("Writing to %s" % args.output)
        pandas_to_csv(df, args.output)


    @is_loaded
    def do_summary_extended(self, line):
        """
        Summarize contributions of each subflow
        For now it is naive, does not look at retransmissions ?
        """
        parser = gen_bicap_parser("mptcp", True)
        parser.description = """
            Look into more details of an mptcp connection
            """

        args = parser.parse_args(shlex.split(line))

        basic_stats = stats.mptcp_compute_throughput(
            args.pcap1, args.streamid,
            args.dest
        )

        df = load_merged_streams_into_pandas(
            args.pcap1,
            args.pcap2,
            args.streamid,
            args.streamid2,
            args.protocol == "mptcp",
            self.tshark_config
        )

        success, ret = stats.mptcp_compute_throughput_extended(
                # self.data, args.mptcpstream, args.destination
                df,
                basic_stats,
                args.destination

        )
        if success is not True:
            self.perror("Throughput computation failed:")
            self.perror(ret)
            return

        total_transferred = ret["mptcp_bytes"]
        self.poutput("mptcpstream %d transferred %d" % (ret["mptcpstreamid"], ret["mptcp_bytes"]))
        for tcpstream, sf_bytes in map(lambda sf: (sf["tcpstreamid"], sf["bytes"]), ret["subflow_stats"]):
            subflow_load = sf_bytes/ret["mptcp_bytes"]
            self.poutput('tcpstream %d transferred %d out of %d, accounting for %f%%' % (
                tcpstream, sf_bytes, total_transferred, subflow_load*100))

    @is_loaded
    def do_list_connections(self, *args):
        """
        List mptcp connections via their ids (mptcp.stream)
        """
        streams = self.data.groupby("mptcpstream")
        # TODO use ppaged instead ?
        self.poutput('%d mptcp connection(s)' % len(streams))
        for mptcpstream, group in streams:
            self.list_subflows(mptcpstream)


    @experimental
    def do_print_owds(self, line):

        parser = gen_bicap_parser("tcp")
        parser.description = """This function tries merges a tcp stream from 2 pcaps
                            in an attempt to print owds. See map_tcp_connection first maybe."""

        parser.add_argument("protocol", action="store", choices=["mptcp", "tcp"], help="tcp.stream id visible in wireshark")
        parser.add_argument("--destination", action="store", choices=DestinationChoice, help="tcp.stream id visible in wireshark")
        # give a choice "hash" / "stochastic"
        # parser.add_argument("--map-packets", action="store", type=int, help="tcp.stream id visible in wireshark")
        parser.add_argument(
            '-v', '--verbose', dest="verbose", default=False,
            action="store_true",
            help="how to display each connection"
        )

        args = parser.parse_args(shlex.split(line))
        print("Loading merged streams")
        df = load_merged_streams_into_pandas(
            args.pcap1,
            args.pcap2,
            args.streamid,
            args.streamid2,
            args.protocol == "mptcp",
            self.tshark_config
        )
        result = df
        print("%r" % result)
        print(result[mpdata.TCP_DEBUG_FIELDS].head(20))

        print("print_owds finished")
        # print("TODO display before doing plots")
        # TODO display errors
        print(result[["owd"]].head(20))
        # print(result.columns)
        mpdata.print_weird_owds(result)
        # print(result[["owd"]].head(20))

    def do_check_tshark(self, line):
        """
        Check your tshark/wireshark version
        """
        print("TODO implement automated check")
        print("you need a wireshark > 19 June 2018 with commit dac91db65e756a3198616da8cca11d66a5db6db7...")


    @with_category(CAT_MPTCP)
    @experimental
    def do_qualify_reinjections(self, line):
        """
        test with:
            mp qualify_reinjections 0

        TODO move the code into a proper function
        """
        parser = gen_bicap_parser("mptcp")
        parser.description = """
            Qualify reinjections of the connection.
            You might want to run map_mptcp_connection first to find out 
            what map to which
            """

        args = parser.parse_args(shlex.split(line))

        df_all = load_merged_streams_into_pandas(
            args.pcap1,
            args.pcap2,
            args.mptcpstream,
            args.mptcpstream2,
            mptcp=True,
            tshark_config=self.tshark_config
            )


        # adds a redundant column
        df = classify_reinjections(df_all)

        # keep only those that matched both for now
        print("MATT %d df packets" % len(df))
        
        # print(df_all[ pd.notnull(df_all[_sender("reinjection_of")])] [
        #     _sender(["reinjection_of", "reinjected_in", "packetid", "reltime"]) +
        #     _receiver(["packetid", "reltime"])
        # ])

        # to help debug
        # df.to_excel("temp.xls")

        def _print_reinjection_comparison(original_packet, reinj):
            """
            Expects tuples of original and reinjection packets
            """
            # original_packet  = sender_df.loc[ sender_df.packetid == initial_packetid, ].iloc[0]
            row = reinj
            # print(original_packet["packetid"])
            print("packet {pktid} is a successful_reinjection of {initial_packetid}."
                    " It arrived at {reinjection_arrival} to compare with {original_arrival}"
                    " while being transmitted at {reinjection_start} to compare with {original_start}"
                    .format(
                pktid               = getattr(row, _sender("packetid")),
                initial_packetid    = initial_packetid,
                
                reinjection_start   = getattr(row, _sender("abstime")),
                reinjection_arrival = getattr(row, _receiver("abstime")),
                original_start      = original_packet[ _sender("abstime") ],
                original_arrival    = original_packet[ _receiver("abstime") ] 
            ))

            if getattr(row, _receiver("abstime")) > original_packet[ _receiver("abstime") ]:
                print("BUG: this is not a valid reinjection after all ?")

        # print("debugging ")
        print("dataframe size = %d" % len(df))

        # with pd.option_context('display.max_rows', None, 'display.max_columns', 300):
        #     print(reinjected_packets[["packetid", "packetid_receiver", *_receiver(["reinjected_in", "reinjection_of"])]].head())


        for destination in ConnectionRoles:
            self.poutput("looking for reinjections towards mptcp %s" % destination)
            sender_df = df[ df.mptcpdest == destination]

            # TODO we now need to display successful reinjections
            reinjections = sender_df[ pd.notnull(sender_df[ _sender("reinjection_of") ]) ]

            print("=================================="
                "=====       TESTING          ====="
                "==================================")

            print("reinjections")
            print(reinjections[ _sender(["packetid", "reinjection_of"]) ])

            successful_reinjections = reinjections[ reinjections.redundant == False ]

            self.poutput("%d successful reinjections" % len(successful_reinjections))
            print(successful_reinjections[ _sender(["packetid", "reinjection_of"]) + _receiver(["packetid"]) ])

            for row in successful_reinjections.itertuples(index=False):
                # print("full row %r" % (row,))

                # loc ? this is an array, sort it and take the first one ?
                # initial_packetid = getattr(row, _sender("reinjection_of")),
                initial_packetid = row.reinjection_of[0]
                # print("initial_packetid = %r %s" % (initial_packetid, type(initial_packetid)))

                original_packet  = df_all.loc[ df_all.packetid == initial_packetid ].iloc[0]
                # print("original packet = %r %s" % (original_packet, type(original_packet)))

                _print_reinjection_comparison(original_packet, row)

                

    @with_category(CAT_MPTCP)
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
        # print("WARNING: Requires (until upstreaming) a custom wireshark:\n"
        #     "Check out https://github.com/teto/wireshark/tree/reinject_stable"
        # )
        parser = argparse.ArgumentParser(
            description="Listing reinjections of the connection"
        )
        parser.add_argument("mptcpstream", type=int, help="mptcp.stream id")
        parser.add_argument("--summary", action="store_true", default=False,
                help="Just count reinjections")

        args = parser.parse_args(line)
        df = self.data
        df = self.data[df.mptcpstream == args.mptcpstream]
        if df.empty:
            self.poutput("No packet with mptcp.stream == %d" % args.mptcpstream)
            return

        # known : Set[int] = set()
        # print(df.columns)

        # TODO move to outer function ?
        # TODO use ppaged
        reinjections = df.dropna(axis=0, subset=["reinjection_of"] )
        total_nb_reinjections = 0
        output = ""
        for row in reinjections.itertuples():
            # if row.packetid not in known:
            # ','.join(map(str,row.reinjection_of)
            output += ("packetid=%d (tcp.stream %d) is a reinjection of %d packet(s): " %
                (row.packetid, row.tcpstream, len(row.reinjection_of)))

            # print("reinjOf=", row.reinjection_of)
            # assuming packetid is the index
            for pktId in row.reinjection_of:
                # print("packetId %d" % pktId)
                # entry = self.data.iloc[ pktId - 1]
                entry = self.data.loc[ pktId ]
                # entry = df.loc[ df.packetid == pktId]
                # print("packetId %r" % entry)
                output += ("- packet %d (tcp.stream %d)" % (entry.packetid, entry.tcpstream))
            # known.update([row.packetid] + row.reinjection)

        self.ppaged(output)
        # reinjections = df["reinjection_of"].dropna(axis=0, )
        # print("number of reinjections of ")


    def load(self, filename, regen: bool=False):

        self.data = load_into_pandas(filename, self.tshark_config, regen)
        self.prompt = "%s> " % os.path.basename(filename)


    parser = argparse_completer.ACArgumentParser(description='Generate MPTCP stats & plots')
    parser.add_argument("input_file", action="store",
        help="Either a pcap or a csv file (in good format)."
        "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
        "If it can't find one (or with the flag --regen), it will generate a "
        "csv from the pcap with the external tshark program.")
    parser.add_argument(
        "--regen", "-r", action="store_true",
        help="Force the regeneration of the cached CSV file from the pcap input")
    @with_argparser(parser)
    def do_load_pcap(self, args):
        """
        Load the file as the current one
        """
        self.load(args.input_file, args.regen)

    complete_load_pcap = cmd2.Cmd.path_complete


    # def complete_plot(self, text, line, begidx, endidx):
    #     # print("available plots", self.list_available_plots())
    #     index_dict = \
    #         {
    #             1: self.list_available_plots(),  # Tab-complete food items at index 1 in command line
    #             2: self.list_available_plots(),  # Tab-complete food items at index 1 in command line
    #             # 2: sport_item_strs,  # Tab-complete sport items at index 2 in command line
    #             # 3: self.path_complete,  # Tab-complete using path_complete function at index 3 in command line
    #         }
    #     return self.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

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

    # def help_plot(self):
    #     self.do_plot("-h")


    # fake_parser = argparse_completer.ACArgumentParser(description='Generate MPTCP stats & plots')

    # load_pcap1 = fake_parser.add_argument("pcap1", action="store", help="first to load")
    # setattr(load_pcap1, argparse_completer.ACTION_ARG_CHOICES, ('path_complete', [False, False]))

    # @with_argparser_and_unknown_args(fake_parser)
    # def do_plot(self, cli_args, unknown):
    def do_plot(self, cli_args, ):
        """
        global member used by others do_plot members *
        Loads required dataframes when necessary
        """
        # self.plot_parser = argparse_completer.ACArgumentParser(description='Generate MPTCP stats & plots')
        self.plot_parser = argparse.ArgumentParser(description='Generate MPTCP stats & plots')

        subparsers = self.plot_parser.add_subparsers(dest="plot_type", title="Subparsers",
            help='sub-command help',)
        subparsers.required = True  # type: ignore

        # self.plot_parser.add_argument(
        #     'destination',
        #     action="store",
        #     choices=DestinationChoice,
        #     type=lambda x: mp.ConnectionRoles[x],
        #     help='Filter flows according to their direction'
        #     '(towards the client or the server)'
        #     'Depends on mptcpstream'
        # )

        # setattr(self.do_plot.cmd_wrapper, 'argparse', self.plot_parser)

        def register_plots(ext, subparsers):
            """Adds a parser per plot"""
            # check if dat is loaded
            parser = ext.obj.default_parser()
            assert parser, "Forgot to return parser"
            subparsers.add_parser(ext.name, parents=[parser], add_help=False)

        self.plot_mgr.map(register_plots, subparsers)


        cli_args = shlex.split(cli_args)
        args, unknown_args = self.plot_parser.parse_known_args(cli_args)
        # Allocate plot object
        plotter = self.plot_mgr[args.plot_type].obj

        # TODO reparse with the definitive parser ?

        # 'converts' the namespace to for the syntax define a dict
        dargs = vars(args)  

        # workaround argparse limitations to set as default both directions
        dargs.update(destinations= dargs.get("destinations") or mp.ConnectionRoles)
        dataframes = plotter.preprocess(**dargs)
        assert dataframes is not None, "Preprocess must return a list"
        # pass unknown_args too ?
        result = plotter.run(dataframes, **dargs)
        plotter.postprocess(result, **dargs)
    

    # def complete_plot(self, text, line, begidx, endidx):

    #     print("complete plot")
        
    #     # look at https://github.com/python-cmd2/cmd2/blob/master/examples/tab_autocompletion.py#L528
    #     library_subcommand_groups = {'plot_type': None}


    #     completer = argparse_completer.AutoCompleter(self.plot_parser,
    #             )
    #     # subcmd_args_lookup=library_subcommand_groups)
    #     tokens, _ = self.tokens_for_completion(line, begidx, endidx)
    #     print("tokens", tokens)
    #     results = completer.complete_command(tokens, text, line, begidx, endidx)
    #     return results



    @with_category(CAT_GENERAL)
    def do_clean_cache(self, line):
        """
        mptcpanalyzer saves pcap to csv converted files in a cache folder, (most likely
        $XDG_CACHE_HOME/mptcpanalyzer). This commands clears the cache.
        """
        cache =  mp.get_cache()
        self.poutput("Cleaning cache [%s]" % cache.folder)
        cache.clean()

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
    def do_quit(self, *args):
        """
        Quit/exit program
        """
        print("Thanks for flying with mptcpanalyzer.")
        return True

    def do_EOF(self, line):
        """
        Keep it to be able to exit with CTRL+D
        """
        return True

    def preloop(self):
        """
        Executed once when cmdloop is called
        """
        histfile = self.config["mptcpanalyzer"]['history']
        if readline and os.path.exists(histfile):
            log.debug("Loading history from %s" % histfile)
            readline.read_history_file(histfile)

    def postloop(self):
        histfile = self.config["mptcpanalyzer"]['history']
        if readline:
            log.debug("Saving history to %s" % histfile)
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

    parser.add_argument(
        "--load", "-l", dest="input_file",
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
        "--no-cache", "-r", action="store_true", default=False,
        help="mptcpanalyzer creates a cache of files in the folder "
        "$XDG_CACHE_HOME/mptcpanalyzer or ~/.config/mptcpanalyzer."
        "Force the regeneration of the cached CSV file from the pcap input"
    )
    parser.add_argument(
        "--cachedir", action="store", type=str,
        help="mptcpanalyzer creates a cache of files in the folder "
        "$XDG_CACHE_HOME/mptcpanalyzer or ~/.config/mptcpanalyzer."
        "Force the regeneration of the cached CSV file from the pcap input"
    )

    args, unknown_args = parser.parse_known_args(arguments)

    # Perform surgery on sys.argv to remove the arguments which have already been processed by argparse
    sys.argv = sys.argv[:1] + unknown_args

    config = MpTcpAnalyzerConfig(args.config)

    # TODO use sthg better like flent/alot do (some update mechanism for instance)
    if args.cachedir:
        config["mptcpanalyzer"]["cache"] = args.cachedir  # type: ignore

    # setup global variables
    mp.__CACHE__ = mc.Cache(config.cachedir, disabled=args.no_cache)
    mp.__CONFIG__ = config

    level = logging.CRITICAL - min(args.debug, 4) * 10
    log.setLevel(level)
    print("Log level set to %s " % logging.getLevelName(level))

    log.debug("Starting in folder %s" % os.getcwd())
    # log.debug("Pandas version: %s" % pd.show_versions())
    log.debug("Pandas version: %s" % pd.__version__)
    log.debug("cmd2 version: %s" % cmd2.__version__)

    try:

        analyzer = MpTcpAnalyzerCmdApp(config, **vars(args))

        if args.input_file:
            log.info("Loading input file %s" % args.input_file)
            cmd = args.input_file
            analyzer.do_load_pcap(cmd)

        log.info("Starting interactive mode")
        analyzer.cmdloop()

    except Exception as e:
        print("An error happened:\n%s" % e)
        print("Displaying backtrace:\n")
        traceback.print_exc()
        return 1
    finally:
        return 0


if __name__ == '__main__':
    main()
