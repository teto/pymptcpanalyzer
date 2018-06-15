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
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.tshark import TsharkConfig
from mptcpanalyzer.version import __version__
import mptcpanalyzer.data as mpdata
from mptcpanalyzer.data import map_mptcp_connection, load_into_pandas, map_tcp_stream, merge_mptcp_dataframes_known_streams, merge_tcp_dataframes_known_streams, load_merged_streams_into_pandas
from mptcpanalyzer.metadata import Metadata
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection, MpTcpMapping, TcpMapping
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

# def format_tcp_mapping(main: TcpConnection, mapped: TcpMapping):
#     )

histfile_size = 1000

CAT_REINJECTIONS = "Reinjections"

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


def custom_tshark(f):

    print("WARNING: May requires a custom wireshark (until upstreaming):\n"
        "Check out https://github.com/teto/wireshark/tree/reinject_stable"
    )
    return f

def experimental(f):
    """
    Decorator checking that dataset has correct columns
    """
    print("WORK IN PROGRESS, RESULTS MAY BE WRONG")
    print("Please read the help.")
    return f


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
        self.allow_cli_args = False;  # disable autoload of transcripts
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
        self.poutput("Description of mptcp.stream %d " % mptcpstreamid)

        self.poutput("The connection has %d subflow(s) (client/server): " % (len(con.subflows())))
        for sf in con.subflows():
            self.poutput("\t%s" % sf)

    def help_list_subflows(self):
        print("Use parser -h")

    def complete_list_subflows(self, text, line, begidx, endidx):
        """ help to complete the args """
        # conversion to set removes duplicate keys
        l = list(set(self.data["mptcpstream"]))
        # convert items to str else it won't be used for completion
        l = [str(x) for x in l]

        return l

    def do_map_tcp_connection(self, line):
        parser = argparse.ArgumentParser(
            description="This function tries to map a tcp.stream id from one pcap"
                        " to one in another pcap"
                        "in another dataframe. "
        )

        parser.add_argument("pcap1", action="store", help="first to load")
        parser.add_argument("pcap2", action="store", help="second pcap")
        parser.add_argument("tcpstreamid", action="store", type=int, help="tcp.stream id visible in wireshark")
        parser.add_argument(
            '-v', '--verbose', dest="verbose", default=False,
            action="store_true",
            help="how to display each connection"
        )

        args = parser.parse_args(shlex.split(line))
        df1 = load_into_pandas(args.pcap1, self.tshark_config)
        df2 = load_into_pandas(args.pcap2, self.tshark_config)

        main_connection = TcpConnection.build_from_dataframe(df1, args.tcpstreamid)

        mappings = map_tcp_stream(df2, main_connection)

        print("%d mapping(s) found" % len(mappings))

        for match in mappings:

            formatted_output = main.format_mapping(match)
            # output = "{c1.tcpstreamid} <-> {c2.tcpstreamid} with score={score}"
            # formatted_output = output.format(
            #     c1=main_connection,
            #     c2=match,
            #     score=score
            # )
            print(formatted_output)

    @experimental
    def do_map_mptcp_connection(self, line):
        """
        Tries to map mptcp.streams from different pcaps.
        Score based mechanism

        Todo:
            - Limit number of displayed matches
        """
        parser = argparse.ArgumentParser(
            description="This function tries to map a mptcp.stream from a dataframe"
                        "(aka pcap) to mptcp.stream"
                        "in another dataframe. "
        )

        parser.add_argument("pcap1", action="store", type=str, help="first to load")
        parser.add_argument("pcap2", action="store", type=str, help="second pcap")
        parser.add_argument("mptcpstreamid", action="store", type=int, help="to filter")
        parser.add_argument(
            '-v', '--verbose', dest="verbose", default=False,
            action="store_true",
            help="how to display each connection"
        )

        args = parser.parse_args(shlex.split(line))
        df1 = load_into_pandas(args.pcap1, self.tshark_config)
        df2 = load_into_pandas(args.pcap2, self.tshark_config)


        main_connection = MpTcpConnection.build_from_dataframe(df1, args.mptcpstreamid)
        mappings = map_mptcp_connection(df2, main_connection)


        print("%d mapping(s) found" % len(mappings))
        for match in mappings:

            winner_like = match.score == float('inf')

            # output = "{c1.tcpstreamid} <-> {c2.tcpstreamid} with score={score}"
            output = "{c1.mptcpstreamid} <-> {c2.mptcpstreamid} with score={score} {extra}"
            formatted_output = output.format(
                c1=main_connection,
                c2=match.mapped,
                score=match.score,
                # self.color('red',
                extra= " <-- should be a correct match" if winner_like else ""
            )

            if winner_like:
                # print("MAIN %r" % main_connection)
                # print("MAPPED %r" % match.mapped)
                # print("subflow_mappings %r" % match.subflow_mappings)
                # print subflow mapping
                # if the score is good we do more work to map subflows as well
                # mapped_subflows = _map_subflows(main_connection, match.mapped)

                # match = MpTcpMapping(match.mapped, match.score, mapped_subflows)
                def _print_subflow(x):
                    return "\n-" + x[0].format_mapping(x[1])
                    
                
                formatted_output += ''.join( [ _print_subflow(x) for x in match.subflow_mappings])
            else:
                continue

            print(formatted_output)
        # TODO split into 
        # sauce = self.select('sweet salty', 'Sauce? ')

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

        parser.add_argument(
            'destination',
            action="store",
            choices=mp.CustomConnectionRolesChoices([e.name for e in mp.ConnectionRoles]),
            type=lambda x: mp.ConnectionRoles[x],
            help='Filter flows according to their direction'
            '(towards the client or the server)'
            'Depends on mptcpstream'
        )

        args = parser.parse_args(shlex.split(line))
        df = self.data
        mptcpstream = args.mptcpstream

        success, ret = stats.mptcp_compute_throughput(
                self.data, args.mptcpstream, args.destination
        )
        if success is not True:
            print("Throughput computation failed:")
            print(ret)
            return

        total_transferred = ret["total_bytes"]
        print("mptcpstream %d transferred %d" % (ret["mptcpstreamid"], ret["total_bytes"]))
        for tcpstream, sf_bytes in map(lambda sf: (sf["tcpstreamid"], sf["bytes"]), ret["subflow_stats"]):
            subflow_load = sf_bytes/ret["total_bytes"]
            print('tcpstream %d transferred %d out of %d, accounting for %f%%' % (
                tcpstream, sf_bytes, total_transferred, subflow_load*100))

        # TODO check for reinjections etc...

    @is_loaded
    def do_list_connections(self, *args):
        """
        List mptcp connections via their ids (mptcp.stream)
        """
        streams = self.data.groupby("mptcpstream")
        self.poutput('%d mptcp connection(s)' % len(streams))
        for mptcpstream, group in streams:
            self.list_subflows(mptcpstream)


    @experimental
    # @with_category(CAT_REINJECTIONS)
    # print tcp owd
    def do_print_owds(self, line):
        parser = argparse.ArgumentParser(
            description="This function tries merges a tcp stream from 2 pcaps"
                        "in an attempt to print owds. See map_tcp_connection first maybe."
        )

        parser.add_argument("pcap1", action="store", help="first to load")
        parser.add_argument("pcap2", action="store", help="second pcap")
        parser.add_argument("streamid", action="store", type=int, help="tcp.stream id visible in wireshark")
        parser.add_argument("streamid2", action="store", type=int, help="tcp.stream id visible in wireshark")
        parser.add_argument("protocol", action="store", choices=["mptcp", "tcp"], help="tcp.stream id visible in wireshark")
        # give a choice "hash" / "stochastic"
        # parser.add_argument("--map-packets", action="store", type=int, help="tcp.stream id visible in wireshark")
        parser.add_argument(
            '-v', '--verbose', dest="verbose", default=False,
            action="store_true",
            help="how to display each connection"
        )

        args = parser.parse_args(shlex.split(line))
        df = load_merged_streams_into_pandas(
            args.pcap1,
            args.pcap2,
            args.streamid,
            args.streamid2,
            args.protocol == "mptcp"
        )
        result = df
        print(result[mpdata.DEBUG_FIELDS].head(20))

        print("print_owds finished")
        # print("TODO display before doing plots")
        # TODO display errors
        print(result[["owd"]].head(20))
        # print(result.columns)
        mpdata.print_weird_owds(result)
        # print(result[["owd"]].head(20))

    def do_check_tshark(self, line):
        """
        """
        print("Checking wireshark settings...")
        print("TODO")
        # print("Checking wireshark settings...")
        # TsharkConfig config 
        # config.check_fields


    @experimental
    # put when cmd2 gets bumped to 0.8.5
    # @with_category(CAT_REINJECTIONS)
    def do_qualify_reinjections(self, line):
        """
        test with:
            mp qualify_reinjections 0
        """
        parser = argparse.ArgumentParser(
            description="""
            Qualify reinjections of the connection.
            You might want to run map_mptcp_connection first to find out 
            what map to which
            """
        )
        parser.add_argument("pcap1", type=str, help="Capture file 1")
        parser.add_argument("pcap2", type=str, help="Capture file 2")
        parser.add_argument("mptcpstream", type=int, help="mptcp.stream id")
        # TODO le rendre optionnel ?
        parser.add_argument("mptcpstream2", type=int, help="mptcp.stream id")


        args = parser.parse_args(shlex.split(line))

        df = load_merged_streams_into_pandas(
            args.pcap1,
            args.pcap2,
            args.mptcpstream,
            args.mptcpstream2,
            mptcp=True
            )
        # todo we need to add 
        # res['mptcpdest'] = dest.name

        # df1 = load_into_pandas(args.pcap1, self.tshark_config)
        # df2 = load_into_pandas(args.pcap2, self.tshark_config)
        # con1 = MpTcpConnection.build_from_dataframe(df1, args.mptcpstream)
        # con2 = MpTcpConnection.build_from_dataframe(df2, args.mptcpstream2)
        # df_merged = merge_mptcp_dataframes_known_streams(
        #     (df1, con1),
        #     (df2, con2)
        # )
        # print(df_merged.head(30))

        # reinjections = df[['tcpstream', "reinjection_of"]].dropna(axis=0, )
        reinjections = df[['tcpstream', "reinjected_in"]].dropna(axis=0, )
        total_nb_reinjections = 0
        df["best_reinjection"] = np.nan  # or -1
        for row in reinjections.itertuples():
            print("full row %r" % (row,))
            print("%r" % (row.reinjected_in,))
            # set it to the maximum possible value
            min_rcvtime = sys.maxsize

            # packet id
            successful_reinjection = row.packetid
            for pktid in row.reinjected_in:
                # look for the packet with lowest rcvtime
                # mark it as the best reinjection

                # mark 
                rcvtime = df.loc[ pktid, ""].abstime_receiver
                if rcvtime < min_rcvtime:
                    min_rcvtime = rcvtime
                    successful_reinjection = row.packetid

                

        # as an improvement one can mark how late the reinjection arrived

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
        #     # query = "mptcprole == '%s'" % (ConnectionRoles.Client)
        #     # res = df_merged.query(query)
        #     # isnull / notnull
        #     # reinjections = df[["packetid", 'tcpstream', "reinjections"]].dropna(axis=0, )# subset="reinjections")

        #     # filter packets to only keep the original packets that are reinjected
        #     res2 = res[pd.isnull(res["reinjection_of"])]
        #     res2 = res2[pd.notnull(res["reinjected_in"])]
        #     print("filtering reinjected %d" % (len(res2)))

    @custom_tshark
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
        reinjections = df[['tcpstream', "reinjection_of"]].dropna(axis=0, )
        total_nb_reinjections = 0
        for row in reinjections.itertuples():
            # if row.packetid not in known:
            # ','.join(map(str,row.reinjection_of)
            self.output("packetid=%d (tcp.stream %d) is a reinjection of %d packet(s): " 
                    % ( row.Index, row.tcpstream,
                        len(row.reinjection_of)
                        )
            )

            # print("reinjOf=", row.reinjection_of)
            # assuming packetid is the index
            for pktId in row.reinjection_of:
                # print("packetId %d" % pktId)
                # entry = self.data.iloc[ pktId - 1]
                entry = self.data.loc[ pktId ]
                # entry = df.loc[ df.packetid == pktId]
                # print("packetId %r" % entry)
                self.poutput("- packet %d (tcp.stream %d)" % (entry.packetid, entry.tcpstream))
            # known.update([row.packetid] + row.reinjection)

        reinjections = df["reinjection_of"].dropna(axis=0, )
        # print("number of reinjections of ")


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
        self.do_plot("-h")

    def complete_plot(self, text, line, begidx, endidx):
        types = self._get_available_plots()
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
        plotter = self.plot_mgr[args.plot_type].obj

        dargs = vars(args)  # 'converts' the namespace to a dict

        dataframes = plotter.preprocess(**dargs)
        assert dataframes is not None, "Preprocess must return a list"
        result = plotter.run(dataframes, **dargs)
        plotter.postprocess(result, **dargs)

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
    if args.cachedir:
        config["mptcpanalyzer"]["cache"] = args.cachedir # type: ignore

    # setup global variables
    mp.__CACHE__ = mc.Cache(config.cachedir)
    mp.__CONFIG__ = config

    level = logging.CRITICAL - min(args.debug, 4) * 10
    log.setLevel(level)
    print("Log level set to %s " % logging.getLevelName(level))

    log.debug("Starting in folder %s" % os.getcwd())
    log.debug("Pandas version: %s" % pd.__version__)
    log.debug("cmd2 version: %s" % cmd2.__version__)

    try:

        analyzer = MpTcpAnalyzerCmdApp(config, **vars(args))

        if args.input_file:
            log.info("Loading input file %s" % args.input_file)
            cmd = args.input_file
            analyzer.do_load_pcap(cmd)

        # if extra parameters passed via the cmd line, consider it is one command
        # if unknown_args:
        #     log.info("One-shot command(s) with unknown_args=  %s" % unknown_args)

        #     for cmd in unknown_args:
        #         analyzer.onecmd(cmd)
        # else:
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
