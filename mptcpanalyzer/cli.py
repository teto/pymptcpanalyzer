# -*- coding: utf8
# PYTHON_ARGCOMPLETE_OK
# vim: set et fenc=utf-8 ff=unix sts=4 sw=4 ts=4 :

# Copyright 2015-2016 Université Pierre et Marie Curie
# Copyright 2017-2019 IIJ Initiative for Internet Japan
#
# Matthieu coudron, coudron@iij.ad.jp
"""
# the PYTHON_ARGCOMPLETE_OK line a few lines up can enable shell completion
for argparse scripts as explained in
- http://dingevoninteresse.de/wpblog/?p=176

todo test https://github.com/jonathanslenders/python-prompt-toolkit/tree/master/examples/tutorial
"""
import argparse
# argparse.cmd2_parser_module = 'mptcpanalyzer.parser'
import tempfile
import sys
import logging
import os
import subprocess
import functools
import inspect
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.tshark import TsharkConfig
from mptcpanalyzer.version import __version__
from mptcpanalyzer.parser import gen_bicap_parser, gen_pcap_parser, FilterStream, \
    MpTcpAnalyzerParser, MpTcpStreamId, TcpStreamId
import mptcpanalyzer.data as mpdata
from mptcpanalyzer.topo import load_topology, SubflowLiveStats
from mptcpanalyzer.data import map_mptcp_connection, load_into_pandas, map_tcp_stream, \
    load_merged_streams_into_pandas, classify_reinjections, pandas_to_csv
from mptcpanalyzer import _sender, _receiver
from mptcpanalyzer.connection import MpTcpConnection, TcpConnection, ConnectionRoles
import mptcpanalyzer.cache as mc
from mptcpanalyzer.statistics import mptcp_compute_throughput, tcp_get_stats
import mptcpanalyzer as mp
from mptcpanalyzer import PreprocessingActions, Protocol
import stevedore
import pandas as pd
import shlex
import traceback
import pprint
import textwrap
from typing import List
import cmd2
from cmd2 import with_argparser, with_category
from enum import Enum, auto
import mptcpanalyzer.pdutils
import dataclasses
from colorama import Fore, Back
from mptcpanalyzer.debug import debug_dataframe
from stevedore import extension
from pandas.plotting import register_matplotlib_converters
import bitmath
# from bitmath.integrations.bmargparse import BitmathType

plugin_logger = logging.getLogger("stevedore")
plugin_logger.addHandler(logging.StreamHandler())

# log = logging.getLogger(__name__)

# this catches the "root" logger which is the parent of all loggers
log = logging.getLogger()
# ch = logging.StreamHandler()
# formatter = logging.Formatter('%(name)s:%(levelname)s: %(message)s')
# ch.setFormatter(formatter)

# log.addHandler(ch)
# log.setLevel(logging.DEBUG)
# handler = logging.FileHandler("mptcpanalyzer.log", delay=False)


histfile_size = 1000


LOG_LEVELS = {
    logging.getLevelName(level): level for level in [
        mp.TRACE, logging.DEBUG, logging.INFO, logging.ERROR
    ]
}


# used by bitmath
# :.2f
DEFAULT_UNIT_FMT = "{value} {unit}"

CAT_TCP = "TCP related"
CAT_MPTCP = "MPTCP related"
CAT_GENERAL = "Tool"


FG_COLORS = {
    'black': Fore.BLACK,
    'red': Fore.RED,
    'green': Fore.GREEN,
    'yellow': Fore.YELLOW,
    'blue': Fore.BLUE,
    'magenta': Fore.MAGENTA,
    'cyan': Fore.CYAN,
    'white': Fore.WHITE,
}
BG_COLORS = {
    'black': Back.BLACK,
    'red': Back.RED,
    'green': Back.GREEN,
    'yellow': Back.YELLOW,
    'blue': Back.BLUE,
    'magenta': Back.MAGENTA,
    'cyan': Back.CYAN,
    'white': Back.WHITE,
}

color_off = Fore.RESET + Back.RESET

def is_loaded(f):
    """
    Decorator checking that dataset has correct columns
    """
    @functools.wraps(f)
    def wrapped(self, *args):

        log.debug("Checking if a pcap was already loaded")
        if self.data is not None:
            return f(self, *args)
        else:
            raise mp.MpTcpException("Please load a pcap with `load_pcap` first")
        return
    return wrapped


def experimental(f):
    """
    Decorator checking that dataset has correct columns
    """

    @functools.wraps(f)
    def wrapped(self, *args, **kwargs):
        print("WORK IN PROGRESS, RESULTS MAY BE WRONG")
        return f(self, *args, **kwargs)
    return wrapped


def provide_namespace(cmd2_instance):

    myNs = argparse.Namespace()
    myNs._dataframes = {"pcap": cmd2_instance.data.copy()}
    return myNs


class MpTcpAnalyzerCmdApp(cmd2.Cmd):
    """
    mptcpanalyzer can run into 3 modes:

    #. interactive mode (default):
        an interpreter with some basic completion will accept your commands.
    There is also some help embedded.
    #. if a filename is passed as argument, it will load commands from
    this file otherwise, it will consider the unknow arguments as one command,
     the same that could be used interactively
    """

    intro = textwrap.dedent("""
        Type `help` to list the available commands and `help <command>` or `<command> -h`
        for a detailed help of the command
        """)

    def stevedore_error_handler(self, manager, entrypoint, exception):
        print("Error while loading entrypoint [%s]" % entrypoint)

    def __init__(
        self, cfg: MpTcpAnalyzerConfig,
        human_readable,
        stdin=sys.stdin,
        **kwargs
    ) -> None:
        """
        Args:
            cfg (MpTcpAnalyzerConfig): A valid configuration

        Attributes:
            prompt (str): Prompt seen by the user, displays currently loaded pcpa
            config: configution to get user parameters
            data:  dataframe currently in use
        """

        shortcuts = {
            'lm': 'list_mptcp_connections',
            'lt': 'list_tcp_connections',
            'ls': 'list_subflows',
            'lr': 'list_reinjections'
        }
        self.config = cfg

        super().__init__(
            completekey='tab', stdin=stdin, shortcuts=shortcuts,
            persistent_history_file=self.config["mptcpanalyzer"]['history'],
            allow_cli_args=True,  # disable autoload of transcripts
            allow_redirection=True,  # allow pipes in commands
        )
        self.prompt = FG_COLORS['blue'] + "Ready>" + color_off
        self.data = None  # type: pd.DataFrame
        # TODO should be a proper object
        self.topo = None  # type: ignore
        self.tshark_config = TsharkConfig(
            delimiter=cfg["mptcpanalyzer"]["delimiter"],
            profile=cfg["mptcpanalyzer"]["wireshark_profile"],
        )

        # serves as a default, can be overriden in subcommands
        self.human_readable = human_readable

        # cmd2 specific initialization
        self.default_to_shell = False
        self.debug = True  # for now
        self.set_posix_shlex = True

        # Pandas specific initialization
        # for as long as https://github.com/pydata/numexpr/issues/331 is a problem
        # does not seem to work :s
        pd.set_option('compute.use_numexpr', False)
        pd.set_option('display.max_info_columns', 5)  # verbose dataframe.info
        pd.set_option('mode.chained_assignment', 'raise')  # strict but prevents errors
        # to help with development, will give a stacktrace upon warnings
        # import warnings
        # warnings.simplefilter('error', FutureWarning)
        log.debug("use numexpr? %d" % pd.get_option('compute.use_numexpr'))
        register_matplotlib_converters()

        # Load Plots
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
            # invoke_kwds
            propagate_map_exceptions=True,
            on_load_failure_callback=self.stevedore_error_handler
        )

        self.cmd_mgr = extension.ExtensionManager(
            namespace='mptcpanalyzer.cmds',
            invoke_on_load=True,
            verify_requirements=True,
            invoke_args=(),
            propagate_map_exceptions=False,
            on_load_failure_callback=self.stevedore_error_handler
        )

        #  do_plot parser
        ######################
        # not my first choice but to accomodate cmd2 constraints
        # see https://github.com/python-cmd2/cmd2/issues/498
        subparsers = MpTcpAnalyzerCmdApp.plot_parser.add_subparsers(
            dest="plot_type", required=True,
            title="Available plots",
            parser_class=MpTcpAnalyzerParser,
            help='Consult each plot\'s help via its plot <PLOT_TYPE> -h flag.',
        )

        def register_plots(ext, subparsers):
            """Adds a parser per plot"""
            # check if dat is loaded
            parser = ext.obj.default_parser()
            assert parser, "Forgot to return parser"
            # we can pass an additionnal help
            log.debug("Registering subparser for plot %s" % ext.name)
            subparsers.add_parser(
                ext.name, parents=[parser],
                # parents= just copies arguments, not the actual help !
                description=parser.description,
                epilog=parser.epilog,
                add_help=False,
            )

        self.plot_mgr.map(register_plots, subparsers)
        # will raise NoMatches when no plot available

        # if loading commands from a file, we disable prompt not to pollute output
        if stdin != sys.stdin:
            log.info("Disabling prompt because reading from stdin")
            self.use_rawinput = False
            self.prompt = ""
            self.intro = ""

        self.poutput("Run `checkhealth` in case of issues")
        self.register_postparsing_hook(self.myhookmethod)

    def myhookmethod(self, params: cmd2.plugin.PostparsingData) -> cmd2.plugin.PostparsingData:
        # the statement object created from the user input
        # is available as params.statement
        return params

    def do_checkhealth(self, args):
        if sys.hexversion <= 0x03070000:
            self.perror("This program requires a newer python than %s" % sys.version)

        try:
            self.poutput("Checking for tshark version >= 3.X.X ...")

            out = subprocess.check_output(["tshark", "--version"])
            first_line = out.decode().splitlines()[0]
            import re
            m = re.search(r'([\d.])', first_line)
            major_version = int(m.group(0))
            self.poutput(f"found tshark major version {major_version}")
            if major_version < 3:
                self.perror("Your tshark version seems too old ?!")
            else:
                self.poutput("Your tshark version looks fine")

        except Exception as e:
            self.poutput("An error happened while checking tshark version")
            self.poutput("Run `tshark -v` and check it's >= 3.0.0")
            self.perror("%s" % e)


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
            sys_exit_code = super().cmdloop()
        except KeyboardInterrupt as e:
            pass

        # Exception raised by sys.exit(), which is called by argparse
        # we don't want the program to finish just when there is an input error
        except SystemExit as e:
            sys_exit_code = self.cmdloop()
        except mp.MpTcpException as e:
            print(e)
            sys_exit_code = self.cmdloop()
        except Exception as e:
            log.critical("Unknown error, aborting...")
            log.critical("%s" % e)
            print("Displaying backtrace:\n")
            traceback.print_exc()

        return sys_exit_code

    def postcmd(self, stop, line):
        """
        Override baseclass
        returning true will stop the program
        """
        log.debug("postcmd result for line [%s] => %r", line, stop)

        return True if stop is True else False


    # TODO pass a namespace instead
    def mptcp_stream_range(self):
        return self.data.mptcpstream.dropna().unique()

    def tcp_stream_range(self):
        return self.data.tcpstream.dropna().unique()

    sf_parser = MpTcpAnalyzerParser(description="List subflows of an MPTCP connection")
    # filter stream should be ok ?
    filter_stream = sf_parser.add_argument(
        "mptcpstream", action="store", type=MpTcpStreamId,
        choices_provider=mptcp_stream_range,
        help="Equivalent to wireshark mptcp.stream id")
    # TODO for tests only, fix
    # setattr(filter_stream, argparse_completer.ACTION_ARG_CHOICES, [0, 1, 2])
    sf_parser.add_argument("--all", action="store_true", default=False,
            help="Display advanced information about the connection")
    @with_argparser(sf_parser)
    @with_category(CAT_MPTCP)
    @is_loaded
    def do_list_subflows(self, args):
        """
        list mptcp subflows
                [mptcp.stream id]

        Example:
            ls 0
        """
        self.list_subflows(args.mptcpstream, args.all)

    @is_loaded
    def list_subflows(self, mptcpstreamid: MpTcpStreamId, detailed=False):

        try:
            PREFIX_SF = "  >"
            con = MpTcpConnection.build_from_dataframe(self.data, mptcpstreamid)
            msg = f"mptcp.stream {mptcpstreamid} has %d subflow(s): "
            self.poutput(msg % len(con.subflows()))
            if detailed:
                self.poutput(f"client version: {con.client_version}")
                self.poutput(f"server version: {con.server_version}")
            for sf in con.subflows():
                self.poutput(PREFIX_SF + "%s" % sf)
                if detailed:
                    self.poutput(PREFIX_SF + "interface: %s" % sf.interface)
        except mp.MpTcpMissingKey as e:
            self.poutput(e)
        except mp.MpTcpException as e:
            self.perror(e)

    parser = MpTcpAnalyzerParser(
        description='''
        This function tries to map a tcp.stream id from one pcap
        to one in another pcap in another dataframe.
    ''')

    # TODO use gen_bicap_parser instead
    load_pcap1 = parser.add_argument("pcap1", action="store",
            completer=cmd2.Cmd.path_complete, help="first to load")
    load_pcap2 = parser.add_argument("pcap2", action="store",
           completer=cmd2.Cmd.path_complete, help="2nd pcap.")

    parser.add_argument("tcpstreamid", action="store", type=int,
                        help="tcp.stream id visible in wireshark for pcap1")
    parser.add_argument("--json", action="store_true", default=False,
                        help="Machine readable summary.")
    parser.add_argument('-v', '--verbose',
        dest="verbose", default=False, action="store_true",
        help="how to display each connection")

    parser.epilog = inspect.cleandoc('''
    Examples:
        map_tcp_connection examples/client_1_tcp_only.pcap examples/server_1_tcp_only.pcap  0
    ''')
    @with_argparser(parser)
    @with_category(CAT_TCP)
    def do_map_tcp_connection(self, args):

        df1 = load_into_pandas(args.pcap1, self.tshark_config)
        df2 = load_into_pandas(args.pcap2, self.tshark_config)

        main_connection = TcpConnection.build_from_dataframe(df1, args.tcpstreamid)

        mappings = map_tcp_stream(df2, main_connection)

        self.poutput("Trying to map %s" % main_connection)
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
            self.poutput("%s" % str(match))


    # TODO use biparser instead
    parser = MpTcpAnalyzerParser(
        description="This function tries to map a mptcp.stream from a dataframe"
                    "(aka pcap) to mptcp.stream"
                    "in another dataframe. "
    )

    load_pcap1 = parser.add_pcap("pcap1", action="store", completer=cmd2.Cmd.path_complete,
        help="first to load")
    load_pcap2 = parser.add_pcap("pcap2", action="store", completer=cmd2.Cmd.path_complete,
        help="second pcap")

    parser.add_argument("mptcpstreamid", action="store", type=mp.MpTcpStreamId, help="to filter")
    parser.add_argument("--trim", action="store", type=float, default=0,
                        help="Remove mappings with a score below this threshold")
    parser.add_argument("--limit", action="store", type=int, default=2,
                        help="Limit display to the --limit best mappings")
    parser.add_argument('-v', '--verbose', dest="verbose", default=False, action="store_true",
                        help="display all candidates")

    parser.epilog = inspect.cleandoc('''
        For example run:
        > map_mptcp_connection examples/client_2_redundant.pcapng examples/server_2_redundant.pcapng 0
    ''')
    @with_argparser(parser)
    @with_category(CAT_MPTCP)
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
                score=FG_COLORS['red'] + str(match.score) + color_off,
                extra=" <-- should be a correct match" if winner_like else ""
            )

            if match.score < args.trim:
                continue

            # match = MpTcpMapping(match.mapped, match.score, mapped_subflows)
            def _print_subflow(x):
                return "\n-" + x[0].format_mapping(x[1])

            formatted_output += ''.join([_print_subflow(x) for x in match.subflow_mappings])

            self.poutput(formatted_output)

    # summary_parser = MpTcpAnalyzerParser(
    #     description="Prints a summary of the mptcp connection"
    # )
    def do_list_interfaces(self, args):
        """
        List this monitor available interfaces
        """
        self.poutput("Listing interfaces...")
        names = self.tshark_config.list_interfaces()
        print(names)

    live_parser = MpTcpAnalyzerParser(
        description="Live analysis"
    )
    # todo should look into choices=interfaces
    live_parser.add_argument("interface", action="store")
    @with_argparser(live_parser, with_unknown_args=True)
    def do_live_analysis(self, args, unknown):
        """
        List this monitor available interfaces
        """
        self.poutput("Starting live analysis on...")
        # names = self.tshark_config.list_interfaces()

        # TODO pass the capture filter?
        # here we should
        with tempfile.NamedTemporaryFile() as tmpfile:

            proc = self.tshark_config.monitor(args.interface, tmpfile)

            cmd = [
                # output the last NUM bytes
                "tail", "-f", "-c", "+0", tmpfile.name
            ]
            print("Starting")
            print(cmd)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # env=custom_env
            )
            out, stderr = proc.communicate()
            print("out", out)
            print("err", stderr)


    summary_parser = MpTcpAnalyzerParser(
        description="Prints a summary of the mptcp connection"
    )
    action_stream = summary_parser.filter_stream(
        "tcpstream",
        protocol=mp.Protocol.TCP,
        choices_provider=tcp_stream_range,
        action=mp.parser.retain_stream("pcap"),
    )
    # action_stream = summary_parser.add_argument(
    #     "tcpstream", type=TcpStreamId,
    #     # choices_provider=tcp_stream_range,
    #     action=mp.parser.retain_stream("pcap"),
    #     help="tcp.stream id")
    summary_parser.epilog = inspect.cleandoc('''
        Similar to wireshark's "Follow -> TCP stream"
    ''')
    @is_loaded
    @with_argparser(summary_parser, ns_provider=provide_namespace,
            with_unknown_args=True)
    def do_tcp_summary(self, args, unknown):
        self.poutput("Summary of TCP connection")
        df = self.data

        con = df.tcp.connection(args.tcpstream)
        con.fill_dest(df)

        for dest in ConnectionRoles:
            res = tcp_get_stats(
                self.data, args.tcpstream,
                dest,
                False
            )

            self.poutput(res)

    summary_parser = MpTcpAnalyzerParser(
        description="Prints a summary of the mptcp connection"
    )
    action_stream = summary_parser.filter_stream(
        "mptcpstream",
        # type=MpTcpStreamId,
        protocol=mp.Protocol.MPTCP,
        action=mp.parser.retain_stream("pcap"),
        # help="mptcp.stream id"
    )
    # action_stream = summary_parser.add_argument(
    #     "mptcpstream", type=MpTcpStreamId, action=mp.parser.retain_stream("pcap"),
    #     help="mptcp.stream id")
    # TODO update the stream id autcompletion dynamically ?
    # setattr(action_stream, argparse_completer.ACTION_ARG_CHOICES, range(0, 10))

    # TODO use filter_dest instead
    summary_parser.filter_destination()
    # summary_parser.add_argument(
    #     '--dest',
    #     action=mpparser.AppendDestination,
    #     help='Filter flows according to their direction'
    #     '(towards the client or the server)'
    #     'Depends on mptcpstream'
    # )
    summary_parser.add_argument("--json", action="store_true", default=False,
        help="Machine readable summary.")
    # TODO use default=self.human_readable,
    summary_parser.add_argument(
        "-H", action="store_true", dest="human_readable",
        default=False,
        help="Human-readable dimensions"
    )
    @is_loaded
    @with_argparser(summary_parser, ns_provider=provide_namespace,
        with_unknown_args=True)
    def do_mptcp_summary(self, args, unknown):
        """
        Naive summary contributions of the mptcp connection
        See summary_extended for more details
        """

        df = self.data
        mptcpstream = args.mptcpstream

        df = df.mptcp.fill_dest(mptcpstream)
        best_prefix = self.human_readable if args.human_readable is None else args.human_readable
        print("Using bestprefix ? ", best_prefix)

        with bitmath.format(
            # fmt_str=DEFAULT_UNIT_FMT,
            bestprefix=best_prefix,
            plural=True
        ):
            for destination in args.dest:
                stats = mptcp_compute_throughput(
                    self.data, args.mptcpstream,
                    destination,
                    False
                )

                if args.json:
                    import json
                    val = json.dumps(dataclasses.asdict(stats), ensure_ascii=False)
                    self.poutput(val)
                    return

                # TODO use datetime.precision instead of hardcoding second ?
                # even better if bitmath
                msg = ("mptcp stream {} transferred {} over {duration} sec"
                      "({rate} per second) towards {}.").format(
                    stats.mptcpstreamid,
                    stats.mptcp_throughput_bytes,
                    destination.to_string(),
                    duration=stats.mptcp_duration.total_seconds(),
                    rate=stats.rate
                )
                self.poutput(msg)
                for sf in stats.subflow_stats:
                    sf_tput = sf.throughput_bytes
                    log.log(mp.TRACE, "sf after computation: %r", sf)
                    self.poutput(
                        "tcpstream {} transferred {sf_tput} out of {mptcp_tput}, "
                        "accounting for {tput_ratio:.2f}%".format(
                            sf.tcpstreamid, sf_tput=sf_tput,
                            mptcp_tput=stats.mptcp_throughput_bytes,
                            tput_ratio=sf.throughput_contribution*100
                        ))



    parser = gen_pcap_parser({"pcap": PreprocessingActions.Preload})
    parser.description = "Export connection(s) to CSV"
    parser.epilog = '''

    '''
    parser.add_argument("output", action="store", help="Output filename")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--tcpstream', action=functools.partial(FilterStream, "pcap", False),
            type=TcpStreamId)
    group.add_argument('--mptcpstream', action=functools.partial(FilterStream, "pcap", True),
            type=MpTcpStreamId)

    # TODO check ? use AppendDestination
    parser.add_argument("--destination", action="store",
        choices=mp.DestinationChoice,
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
        # need to compute the destinations before dropping syn from the dataframe
        for streamid, subdf in df.groupby("tcpstream"):
            con = df.tcp.connection(streamid)
            df = con.fill_dest(df)

            if args.drop_syn:
                # use subdf ?
                self.poutput("drop-syn Unsupported yet")
                df.drop(subdf.head(3).index, inplace=True)
                # drop 3 first packets of each connection ?
                # this should be a filter
                syns = df[df.tcpflags == mp.TcpFlags.SYN]

        self.poutput("Writing to %s" % args.output)
        pandas_to_csv(df, args.output)


    sumext_parser = gen_bicap_parser(mp.Protocol.MPTCP, True)
    sumext_parser.add_argument("--json", action="store_true", default=False,
        help="Machine readable summary.")
    sumext_parser.description = inspect.cleandoc("""
        Look into more details of an mptcp connection.
        Requires to have both server and client pcap.
    """)
    sumext_parser.epilog = inspect.cleandoc("""
        > summary_extended examples/client_2_redundant.pcapng 0 examples/server_2_redundant.pcapng 0
    """)
    @with_argparser(sumext_parser, with_unknown_args=True)
    def do_summary_extended(self, args, unknown):
        """
        Summarize contributions of each subflow
        For now it is naive, does not look at retransmissions ?
        """

        self.poutput("Summary extended of mptcp connection ")

        # to abstract things a bit
        destinations = args.pcap_destinations
        # or list(mp.ConnectionRoles)

        # TODO already be done BUT NOT THE CASE FOR GOD's SAKE !
        # TODO we should have the parser do it
        df = load_merged_streams_into_pandas(
            args.pcap1,
            args.pcap2,
            args.pcap1stream,
            args.pcap2stream,
            True,
            self.tshark_config
        )

        for destination in destinations:

            stats = mptcp_compute_throughput(
                df,
                args.pcap1stream,
                destination=destination,
                merged_df=True,
            )

            if args.json:
                import json
                val = json.dumps(dataclasses.asdict(stats), ensure_ascii=False)
                self.poutput(val)
                return

            msg = ("mptcpstream {c.mptcpstreamid} towards {destination} forwarded "
                   "{c.mptcp_throughput_bytes} bytes with a goodput of {c.mptcp_goodput_bytes}")
            self.poutput(msg.format(c=stats, destination=destination.name))

            msg = ("tcpstream {sf.tcpstreamid} analysis:\n"
            "- throughput: transferred {sf.throughput_bytes} out of {mptcp.mptcp_throughput_bytes}"
            " mptcp bytes, accounting for {mptcp_tput_ratio:.2f}% of MPTCP throughput\n"
            "- goodput: transferred {sf.mptcp_goodput_bytes} out of {mptcp.mptcp_goodput_bytes}, "
            "accounting for {mptcp_gput_ratio:.2f}% of MPTCP goodput")

            for subflow in stats.subflow_stats:

                self.poutput(
                    msg.format(
                        mptcp=stats, sf=subflow,
                        mptcp_tput_ratio=subflow.throughput_contribution * 100,
                        mptcp_gput_ratio=subflow.goodput_contribution * 100,
                    )
                )

    @is_loaded
    @with_category(CAT_TCP)
    def do_list_tcp_connections(self, *args):
        """
        List tcp connections via their ids (tcp.stream)
        """
        streams = self.data.groupby("tcpstream")
        self.poutput('%d tcp connection(s)' % len(streams))
        for tcpstream, group in streams:
            con = TcpConnection.build_from_dataframe(self.data, tcpstream)
            self.poutput(str(con))

    @is_loaded
    @with_category(CAT_MPTCP)
    def do_list_mptcp_connections(self, *args):
        """
        List mptcp connections via their ids (mptcp.stream)
        """
        streams = self.data.groupby("mptcpstream")
        self.poutput('%d mptcp connection(s)' % len(streams))
        for mptcpstream, group in streams:
            self.list_subflows(mptcpstream)
            self.poutput("\n")


    parser = MpTcpAnalyzerParser(
        description="Export a pcap that can be used with wireshark to debug ids"
    )
    load_pcap1 = parser.add_argument("imported_pcap", type=str,
    completer=cmd2.Cmd.path_complete,
        help="Capture file to cleanup.")
    parser.add_argument("exported_pcap", type=str, help="Cleaned up file")

    @with_argparser(parser)
    def do_clean_pcap(self, args):
        """
        toto
        """
        msg = "Exporting a clean version of {} in {}"
        self.poutput(msg.format(args.imported_pcap, args.exported_pcap))

        self.tshark_config.filter_pcap(args.imported_pcap, args.exported_pcap)

    # TODO it should be able to print for both
    parser = gen_bicap_parser(mp.Protocol.TCP, True)
    parser.description = inspect.cleandoc("""
        This function tries merges a tcp stream from 2 pcaps
        in an attempt to print owds. See map_tcp_connection first maybe.
    """)

    # TODO add a limit of packets or use ppaged()
    # parser.add_argument("protocol", action="store", choices=["mptcp", "tcp"],
    #     help="tcp.stream id visible in wireshark")
    # give a choice "hash" / "stochastic"
    parser.add_argument(
        '-v', '--verbose', dest="verbose", default=False,
        action="store_true",
        help="how to display each connection"
    )
    parser.add_argument("--csv", action="store", default=None,
        help="Machine readable summary.")
    parser.epilog = inspect.cleandoc('''
    You can run for example:
        map_tcp_connection examples/client_1_tcp_only.pcap examples/server_1_tcp_only.pcap  0
    ''')
    @with_argparser(parser)
    @experimental
    def do_print_owds(self, args):
        """
        TODO options to diagnose errors:
        - print unmapped packets
        - print abnormal OWDs (negative etc)
        """

        self.poutput("Loading merged streams")
        df = args._dataframes["pcap"]
        result = df
        debug_dataframe(result, "merged stream")

        # todo sort by chronological order ?
        # for row in df.itertuples();
        # self.ppaged()

        if args.csv:
            self.poutput("Exporting to csv")
            with open(args.csv, "w") as fd:
                df.to_csv(
                    fd,
                    sep="|",
                    index=False,
                    header=True,
                )

        # print unmapped packets
        print("print_owds finished")
        # print("TODO display before doing plots")
        # TODO display errors
        # with pd.set_option('precision', 20):
        # with pd.option_context('float_format', '{:f}'.format):
        with pd.option_context('precision', 10):
            print(result[["owd"]].head(20))
        mpdata.print_weird_owds(result)


    parser = gen_bicap_parser(Protocol.MPTCP, dest=True)
    parser.description = inspect.cleandoc("""
        Qualify reinjections of the connection.
        You might want to run map_mptcp_connection first to find out
        what map to which
    """)
    parser.epilog = inspect.cleandoc("""
    > qualify_reinjections examples/client_2_redundant.pcapng 1 examples/server_2_redundant.pcapng 1
    """)
    parser.add_argument("--failed", action="store_true", default=False,
        help="List failed reinjections too.")
    parser.add_argument("--csv", action="store_true", default=False,
        help="Machine readable summary.")
    parser.add_argument("--debug", action="store_true", default=False,
        help="Explain decision for every reinjection.")

    @with_argparser(parser, with_unknown_args=True)
    @with_category(CAT_MPTCP)
    def do_qualify_reinjections(self, args, unknown):
        """
        test with:

        """

        print("Qualifying reinjections for stream in destination:")
        destinations = args.pcap_destinations
        print("Looking at destinations %s" % destinations)

        df_all = args._dataframes["pcap"]

        # print("TOTO")
        # print(df_all.head())

        # TODO this should be done automatically right ?
        # remove later
        df_all = load_merged_streams_into_pandas(
            args.pcap1,
            args.pcap2,
            args.pcap1stream,
            args.pcap2stream,
            mptcp=True,
            tshark_config=self.tshark_config
        )
        # con = rawdf.mptcp.connection(mptcpstreamid)
        # q = con.generate_direction_query(destination)

        # adds a redundant column
        df = classify_reinjections(df_all)

        # print(df_all[ pd.notnull(df_all[_sender("reinjection_of")])] [
        #     _sender(["reinjection_of", "reinjected_in", "packetid", "reltime"]) +
        #     _receiver(["packetid", "reltime"])
        # ])

        def _print_reinjection_comparison(original_packet, reinj, ):
            """
            Expects tuples of original and reinjection packets
            """
            # original_packet  = sender_df.loc[ sender_df.packetid == initial_packetid, ].iloc[0]
            row = reinj

            reinjection_packetid = getattr(row, _sender("packetid"))
            reinjection_start = getattr(row, _sender("abstime"))
            reinjection_arrival = getattr(row, _receiver("abstime"))
            original_start = original_packet[_sender("abstime")]
            original_arrival = original_packet[_receiver("abstime")]

            if reinj.redundant is False:
                # print(original_packet["packetid"])
                msg = ("packet {pktid} is a successful reinjection of {initial_packetid}."
                       " It arrived at {reinjection_arrival} to compare with {original_arrival}"
                       " while being transmitted at {reinjection_start} to compare with "
                       "{original_start}, i.e., {reinj_delta} before")
                # TODO use assert instead
                if getattr(row, _receiver("abstime")) > original_packet[_receiver("abstime")]:
                    print("BUG: this is not a valid reinjection after all ?")

            elif args.failed:
                # only de
                msg = "packet {pktid} is a failed reinjection of {initial_packetid}."
            else:
                return

            msg = msg.format(
                pktid=reinjection_packetid,
                initial_packetid=initial_packetid,
                reinjection_start=reinjection_start,
                reinjection_arrival=reinjection_arrival,
                original_start=original_start,
                original_arrival=original_arrival,
                reinj_delta=reinj.reinj_delta,
            )
            self.poutput(msg)


        # with pd.option_context('display.max_rows', None, 'display.max_columns', 300):
        #     print(reinjected_packets[["packetid", "packetid_receiver", *_receiver(["reinjected_in",
        #      "reinjection_of"])]].head())
        # TODO filter depending on --failed and --destinations

        if args.csv:
            self.pfeedback("Exporting to csv")
            # keep redundant
            # only export a subset ?
            # smalldf = df.drop()
            columns = _sender([
                "abstime", "reinjection_of", "reinjected_in", "packetid",
                "tcpstream", "mptcpstream", "tcpdest", "mptcpdest"
            ])
            columns += _receiver(["abstime", "packetid"])
            columns += ["redundant", "owd", "reinj_delta"]

            df[columns].to_csv(
                self.stdout,
                sep="|",
                index=False,
                header=True,
            )
            return

        # TODO  use args.mptcp_destinations instead
        # TODO revert
        # destinations = [ ConnectionRoles.Server ]
        for destination in destinations:

            self.poutput("looking for reinjections towards mptcp %s" % destination)
            sender_df = df[df.mptcpdest == destination]
            log.debug("%d packets in that direction", len(sender_df))

            # TODO we now need to display successful reinjections
            reinjections = sender_df[pd.notnull(sender_df[_sender("reinjection_of")])]
            # self.poutput("looking for reinjections towards mptcp %s" % destination)

            successful_reinjections = reinjections[reinjections.redundant is False]

            self.poutput("%d successful reinjections" % len(successful_reinjections))
            # print(successful_reinjections[ _sender(["packetid", "reinjection_of"]) + _receiver(["packetid"]) ])

            for row in reinjections.itertuples(index=False):

                # loc ? this is an array, sort it and take the first one ?
                initial_packetid = row.reinjection_of[0]
                # print("initial_packetid = %r %s" % (initial_packetid, type(initial_packetid)))

                original_packet = df_all.loc[df_all.packetid == initial_packetid].iloc[0]
                # print("original packet = %r %s" % (original_packet, type(original_packet)))

                # if row.redundant == True and args.failed:
                #   _print_failed_reinjection(original_packet, row, debug=args.debug)

                _print_reinjection_comparison(original_packet, row, )


    reinj_parser = MpTcpAnalyzerParser(
        description="Listing reinjections of the connection"
    )
    reinj_parser.epilog = "Hello there"
    # action= filter_stream
    # TODO check it is taken into account
    # type=MpTcpStreamId, help="mptcp.stream id")
    reinj_parser.filter_stream("mptcpstream", protocol=Protocol.MPTCP)
    reinj_parser.add_argument("--summary", action="store_true", default=False,
            help="Just count reinjections")

    @is_loaded
    @with_argparser(reinj_parser, with_unknown_args=True, ns_provider=provide_namespace)
    @with_category(CAT_MPTCP)
    def do_list_reinjections(self, args, unknown):
        """
        List reinjections
        We want to be able to distinguish between good and bad reinjections
        (like good and bad RTOs).
        A good reinjection is a reinjection for which either:
        - the segment arrives first at the receiver
        - the cumulative DACK arrives at the sender sooner thanks to that reinjection

        To do that, we need to take into account latencies

        """

        df = self.data
        # df = self.data[df.mptcpstream == args.mptcpstream]
        if df.empty:
            self.poutput("No packet with mptcp.stream == %d" % args.mptcpstream)
            return

        reinjections = df.dropna(axis=0, subset=["reinjection_of"])
        output = ""
        for row in reinjections.itertuples():
            output += ("packetid=%d (tcp.stream %d) is a reinjection of %d packet(s):\n" %
                (row.packetid, row.tcpstream, len(row.reinjection_of)))

            # assuming packetid is the index
            for pktId in row.reinjection_of:
                entry = self.data.loc[pktId]
                output += ("- packet %d (tcp.stream %d)\n" % (entry.packetid, entry.tcpstream))
            # known.update([row.packetid] + row.reinjection)

        self.ppaged(output,)
        # reinjections = df["reinjection_of"].dropna(axis=0, )
        # print("number of reinjections of ")

    parser = MpTcpAnalyzerParser(description="Loads a pcap to analyze")
    parser.add_pcap("input_file")
    # parser.add_argument("input_file", action=LoadSinglePcap,
    #     help="Either a pcap or a csv file."
    #     "When a pcap is passed, mptcpanalyzer looks for a cached csv"
    #     "else it generates a "
    #     "csv from the pcap with the external tshark program."
    # )
    @with_argparser(parser)
    def do_load_pcap(self, args):
        """
        Load the file as the current one
        """
        # print(args)

        self.poutput("Loading pcap %s" % args.input_file)
        self.data = args._dataframes["input_file"]
        self.prompt = "%s> " % os.path.basename(args.input_file)

    parser = MpTcpAnalyzerParser(
        description="Loads a json topology generated by https://github.com/teto/mptcp-pm"
    )
    parser.add_argument(
        "input_file", action="store", type=str,
        completer=cmd2.Cmd.path_complete,
        help="Json file"
    )
    @with_argparser(parser)
    def do_load_topo(self, args):
        """
        Loads a topo generated by https://github.com/teto/mptcp-pm
        """
        # print(args)

        self.poutput("Loading topology %s" % args.input_file)
        self.topo = load_topology(args.input_file)
        print(self.topo)


    def do_mptcp_required_buffer(self, args):
        self.poutput("Make sure the buffer size is ok")

        subflows = []
        for sfdict in self.topo["subflows"]:
            sfdict.pop("dstIp")
            sfdict.pop("srcIp")
            sfdict.pop("srcPort")
            sfdict.pop("dstPort")
            sfdict.pop("cc")
            sfdict.pop("reordering")
            sfdict.pop("rmem")
            sfdict.pop("wmem")
            # sfdict.pop("tcp_state")

            sf = SubflowLiveStats(**sfdict)
            subflows.append(sf)


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


    plot_parser = MpTcpAnalyzerParser(prog='plot', description='Generate plots')
    plot_parser.epilog = inspect.cleandoc('''
        Here are a few plots you can create:

        To plot tcp attributes:
        > plot tcp_attr examples/client_2_filtered.pcapng 0 tcpseq

        To plot one way delays, you need 2 pcaps: from the client and the server side. Then you can run:
        > plot owd tcp examples/client_2_filtered.pcapng 0 examples/server_2_filtered.pcapng 0 --display
    ''')
    @with_argparser(plot_parser, with_unknown_args=True)
    def do_plot(self, args, unknown):
        """
        global member used by others do_plot members *
        Loads required dataframes when necessary
        """

        # Allocate plot object
        plotter = self.plot_mgr[args.plot_type].obj

        # TODO reparse with the definitive parser ?

        # 'converts' the namespace to for the syntax define a dict
        dargs = vars(args)

        dataframes = dargs.pop("_dataframes", {})

        # TODO move to parser
        for pcap, df in dataframes.items():
            res = dargs.pop(pcap, None)
            if res:
                log.debug("Popping %s to prevent a duplicate with the one from _dataframes", pcap)

        # dataframes = args._dataframes.values()
        assert dataframes is not None, "Preprocess must return a list"
        # pass unknown_args too ?
        try:
            # TODO pretty print
            # pp = pprint.PrettyPrinter(indent=4)
            log.debug("Calling plot with dataframes:\n%s and dargs %s", dataframes.keys(), dargs)

            # TODO get formatter keys
            result = plotter.run(**dataframes, **dargs)
        except TypeError as e:
            self.perror("Problem when calling plotter.run")
            self.perror("We passed the following arguments:")
            print(dataframes)
            print(dargs)
            raise e

        self.pfeedback("result %r" % result)
        # to save to file for instance
        plotter.postprocess(result, **dargs)

    @with_category(CAT_GENERAL)
    def do_clean_cache(self, line):
        """
        mptcpanalyzer saves pcap to csv converted files in a cache folder, (most likely
        $XDG_CACHE_HOME/mptcpanalyzer). This commands clears the cache.
        """
        cache = mp.get_cache()
        self.poutput(f"Cleaning cache [{cache.folder}]")
        cache.clean()

    def do_dump(self, args):
        """
        Dumps content of the csv file, with columns selected by the user.
        Mostly used for debug
        """
        parser = argparse.ArgumentParser(description="dumps csv content")
        parser.add_argument('columns', default=["ipsrc", "ipdst"],
            choices=self.data.columns, nargs="*")

        parser.add_argument('-n', default=10, action="store",
            help="Number of results to display")
        args = parser.parse_args(shlex.split(args))
        print(self.data[args.columns])

    def complete_dump(self, text, line, begidx, endidx):
        """
        Should return a list of possibilities
        """
        matches = [x for x in self.data.columns if x.startswith(text)]
        return matches

    # not needed in cmd2
    def do_quit(self, *args):
        """
        Quit/exit program
        """
        self.poutput("Thanks for flying with mptcpanalyzer.")
        return True

    def do_EOF(self, line):
        """
        Keep it to be able to exit with CTRL+D
        """
        return True

    # def preloop(self):
    #     """
    #     Executed once when cmdloop is called
    #     """
    #     histfile = self.config["mptcpanalyzer"]['history']
    #     if readline and os.path.exists(histfile):
    #         log.debug("Loading history from %s" % histfile)
    #         readline.read_history_file(histfile)

    # def postloop(self):
    #     histfile = self.config["mptcpanalyzer"]['history']
    #     if readline:
    #         log.debug("Saving history to %s", histfile)
    #         readline.set_history_length(histfile_size)
    #         readline.write_history_file(histfile)

def main(arguments: List[str] = None):
    """
    This is the entry point of the program

    Args:
        arguments: Made as a parameter since it makes testing easier

    Returns:
        return value will be passed to sys.exit
    """

    if not arguments:
        arguments = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description='Generate MPTCP (Multipath Transmission Control Protocol) stats & plots',
        epilog="You can report issues at https://github.com/teto/mptcpanalyzer",
    )

    parser.add_argument(
        "--load", "-l", dest="input_file",
        help="Either a pcap or a csv file (in good format)."
        "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
        "If it can't find one (or with the flag --regen), it will generate a "
        "csv from the pcap with the external tshark program."
    )
    parser.add_argument('--version', action='version', version=str(__version__))
    parser.add_argument(
        "--config", "-c", action="store",
        help="Path towards the config file. If not set, mptcpanalyzer will try"
        " to load first $XDG_CONFIG_HOME/mptcpanalyzer/config and then "
        " $HOME/.config/mptcpanalyzer/config"
    )
    parser.add_argument(
        "--debug", "-d", choices=LOG_LEVELS.keys(),
        default=logging.getLevelName(logging.ERROR),
        help="More verbose output, can be repeated to be even more "
        " verbose such as '-dddd'"
    )
    parser.add_argument(
        "--no-cache", "--regen", "-r", action="store_true", default=False,
        help="mptcpanalyzer creates a cache of files in the folder "
        "$XDG_CACHE_HOME/mptcpanalyzer or ~/.config/mptcpanalyzer."
        "Force the regeneration of the cached CSV file from the pcap input"
    )
    parser.add_argument(
        "-H", "--human-readable", action="store_true",
        default=False,
        help="Human-readable dimensions"
    )
    # This requires pulling progressbar: TODO wait
    # parser.add_argument(
    #     "--unit", action="store",
    #     type=BitmathType,
    #     default=None,
    #     help="Unit to display size with"
    # )
    parser.add_argument(
        "--cachedir", action="store", type=str,
        help="mptcpanalyzer creates a cache of files in the folder "
        "$XDG_CACHE_HOME/mptcpanalyzer."
    )

    args, unknown_args = parser.parse_known_args(arguments)

    # remove from sys.argv arguments already processed by argparse
    sys.argv = sys.argv[:1] + unknown_args

    config = MpTcpAnalyzerConfig(args.config)

    # TODO use sthg better like flent/alot do (some update mechanism for instance)
    if args.cachedir:
        config["mptcpanalyzer"]["cache"] = args.cachedir  # type: ignore

    # setup global variables
    mp.__CACHE__ = mc.Cache(config.cachedir, disabled=args.no_cache)
    mp.__CONFIG__ = config

    print("Setting log level to %s" % args.debug)
    log.setLevel(LOG_LEVELS[args.debug])
    # logging.basicConfig(format='%(levelname)s:%(message)s', level=LOG_LEVELS[args.debug])

    log.debug("Starting in folder %s", os.getcwd())
    # logging.debug("Pandas version: %s" % pd.show_versions())
    log.debug("Pandas version: %s", pd.__version__)
    log.debug("cmd2 version: %s", cmd2.__version__)

    try:
        analyzer = MpTcpAnalyzerCmdApp(config, **vars(args))

        # enable cmd2 debug only when required
        # analyzer.debug = LOG_LEVELS[args.debug] <= logging.DEBUG

        # could be moved to the class ?
        if args.input_file:
            analyzer.onecmd(f"load_pcap {args.input_file}")

        log.info("Starting interactive mode")
        exit_code = analyzer.cmdloop()
        print("Exit code:", exit_code)

    except Exception as e:
        print("An error happened:\n%s" % e)
        print("Displaying backtrace:\n")
        traceback.print_exc()
        return 1

    return exit_code


if __name__ == '__main__':
    main()
