# -*- coding: utf-8 -*-
import logging
import argparse
from cmd2 import argparse_completer
from typing import Iterable, List, Dict
from .tshark import TsharkConfig
# from .connection import 
from .data import (load_into_pandas, load_merged_streams_into_pandas,
        tcpdest_from_connections, mptcpdest_from_connections)
from . import PreprocessingActions, ConnectionRoles, DestinationChoice, CustomConnectionRolesChoices
from functools import partial


log = logging.getLogger(__name__)


"""

TODO
- action to generate connection 


"""

# TODO add it to a custom MptcpAnalyzerAction
# TODO insert it instead into dict
def _add_dataframe(namespace, dest, df):

    # if not hasattr(namespace, "_dataframes"):
    #     setattr(namespace, "_dataframes", {})
    # namespace._dataframes.update({
    #     dest: df
    # })

    if not hasattr(namespace, "_dataframes"):
        setattr(namespace, "_dataframes", {})

    namespace._dataframes.update({ dest:df})


class DataframeAction(argparse.Action):

    def __init__(self, df_name: str, **kwargs) -> None:
        argparse.Action.__init__(self, **kwargs)

        self.df_name = df_name
        # self.dest = df_name + self.dest

    def add_dataframe(self, namespace, df):
        _add_dataframe(namespace, self.df_name, df)


def StreamId(x):
    return int(x)


class LoadSinglePcap(DataframeAction):
    '''
    Test action !!
    '''
    def __init__(self, loader = TsharkConfig(), **kwargs) -> None:
        super().__init__(df_name=kwargs.get("dest"),  **kwargs)
        self.loader = loader

    def __call__(self, parser, namespace, values, option_string=None):
        if type(values) == list:
            parser.error("lists unsupported")
        else:
            df = load_into_pandas(values, self.loader)

            setattr(namespace, self.dest, values)

        self.add_dataframe (namespace, df)


class AppendDestination(DataframeAction):
    """
    assume convention on naming
    """

    def __init__(self, *args, **kwargs) -> None:
        self.already_called = False
        super().__init__(*args, **kwargs)


    # TODO check if it's called several times
    def __call__(self, parser, namespace, values, option_string=None):

        if self.already_called is False:
            # TODO change the default ?
            setattr(namespace, self.dest, [])

        if type(values) == list:
            print("destination", option_string)
            print("first time called ?", self.already_called)
            if values == []:
                values = list(mp.ConnectionRoles)
                print("empty values, setting these myself")

            # TODO do sthg like append
            setattr(namespace, self.dest, values)
        else:
            print("destination", values)


class MergePcaps(DataframeAction):
    """
    assume convention on naming
    """
    def __init__(self,
        name: str,
        protocol: str, # mptcp or tcp ?
        loader = TsharkConfig(),
        **kwargs
        ) -> None:
        self.loader = loader
        self.protocol = protocol
        DataframeAction.__init__(self, df_name=name, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):

        if type(values) == list:
            parser.error("list unsupported")


        log.debug("Merging pcaps")
        pcap1 = getattr(namespace, self.df_name + "1")
        pcap2 = getattr(namespace, self.df_name + "2")

        pcap1stream = getattr(namespace, self.df_name + "1stream")
        # pcap2stream = getattr(namespace, self.name2 + "stream")
        pcap2stream = values

        assert pcap1
        assert pcap2
        assert pcap1stream is not None
        # assert pcap2stream is not None

        
        #TODO pass clockoffsets
        # Need to add the stream ids too !
        df = load_merged_streams_into_pandas(
            pcap1,
            pcap2,
            pcap1stream,
            pcap2stream,
            self.protocol == "mptcp",
            # TODO how does it get the config
            self.loader,
        )

        # todo actions
        setattr(namespace, self.dest, values)
        # TODO add to merged_dataframes ?
        # setattr(namespace, self.dest + "_merged_df", df)

        self.add_dataframe (namespace, df)


# class ClockOffset(argparse.Action):
#     def __init__(self, df, **kwargs) -> None:
#         argparse.Action.__init__(self, **kwargs)
#
#     def __call__(self, parser, namespace, values, option_string=None):
#         if type(values) == list:
#             # setattr(namespace, self.dest, map(self.validate_ip, values))
#         else:
#             # setattr(namespace, self.dest, self.validate_ip(values))
#             print()


# actually I could use Mptcp vs Tcp filters
# TODO class ExcludeStream
# class ExcludeStream(DataframeAction):

# class QueryAction(argparse.Action):
#     def 

# class ExcludeStream(argparse.Action):
#     def __

def exclude_stream(df_name, mptcp: bool):
    query = "tcpstream"
    if mptcp:
        query = "mp" + query 
    query = query + "!=%d"
    return partial(FilterStream, query, df_name)

def retain_stream(df_name, mptcp: bool):
    query = "tcpstream"
    if mptcp:
        query = "mp" + query 
    query = query + "==%d"
    return partial(FilterStream, query, df_name)



class FilterStream(DataframeAction):
    '''
    To keep a specific stream id
    '''
    def __init__(self, query: str, df_name: str, **kwargs) -> None:
        # self.df_name = df_name
        self.query = query
        # self.mptcp = mptcp
        super().__init__(df_name, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):

        # TODO move to function
        # if self.df_name not in namespace._dataframes:
        #     parser.error("Trying to filter stream in non-registered df %s" % self.df_name)
        #     # TODO set dest

        # make sure result 
        df = namespace._dataframes[self.df_name]

        # streamid = values

        log.debug("Filtering stream %s" % (values))
        log.debug("Applying query %s" % self.query)

        if type(values) != list:
            streamids = list(values)

        # TODO build a query
        for streamid in streamids:

            if mptcp:
                # parser.error("mptcp filtering Unsupported")

                con = MpTcpConnection.build_from_dataframe(dataframe, stream)
                # mptcpdest = main_connection.mptcp_dest_from_tcpdest(tcpdest)
                df = mptcpdest_from_connections(df, con)

            else:
                con = TcpConnection.build_from_dataframe(df, streamid)
                df = tcpdest_from_connections(df, con)
        
        
        df.query(inplace=True)

        # con = TcpConnection.build_from_dataframe(df, args.tcpstream)
        # if args.destination:
        #     self.poutput("Filtering destination")
        #     q = con.generate_direction_query(args.destination)
        #     df = df.query(q)

def gen_bicap_parser(protocol, dest=False):
    """
    protocol in ["mptcp", "tcp"]
    """
    if protocol == "mptcp":
        actions = PreprocessingActions.FilterMpTcpStream | PreprocessingActions.MergeMpTcp
    else:
        actions = PreprocessingActions.FilterTcpStream | PreprocessingActions.MergeTcp
    # action = (PreprocessingActions.Preload | PreprocessingActions.FilterStream | PreprocessingActions.Merge)
    input_pcaps = {
        "pcap": actions,
    }

    # protocol=protocol, 
    return gen_pcap_parser(input_pcaps=input_pcaps, direction=dest)


# map pcaps to a group
def gen_pcap_parser(
        # rename input_pcaps to load_dataframes
        input_pcaps: Dict[str, PreprocessingActions],
        # protocol,
        direction: bool = False,
        parents=[],
        # TODO get rid of this/skip-stream
        skip_subflows: bool = True,
    ) -> argparse_completer.ACArgumentParser:
        """
        Generates a parser with common options.
        This parser can be completed or overridden by its children.

        Args:
            mptcpstream: to accept an mptcp.stream id
            available_dataframe: True if a pcap was preloaded at start
            direction: Enable filtering the stream depending if the packets
            were sent towards the MPTCP client or the MPTCP server
            skip_subflows: Allow to hide some subflows from the plot

        Return:
            An argparse.ArgumentParser

        """
        parser = argparse_completer.ACArgumentParser(
            parents=parents,
            add_help=not parents,
        )

        for df_name, bitfield in input_pcaps.items():

            def _pcap(name, pcapAction="store", filterAction="store"):
                # TODO change the type to expand things etc. like argparse.FileType
                load_pcap = parser.add_argument(name, action=pcapAction, type=str, help='Pcap file')
                setattr(load_pcap, argparse_completer.ACTION_ARG_CHOICES, ('path_complete', [False, False]))
                # TODO add action AddClockOffset
                # parser.add_argument("--clock-offset" + name, action="store", type=int,
                #     help='Offset compared to epoch (in nanoseconds)')

                # or merge ?
                if bitfield & (PreprocessingActions.FilterStream | PreprocessingActions.Merge):
                    # difficult to change the varname here => change it everywhere
                    protocol = "mptcp" if bitfield & PreprocessingActions.FilterMpTcpStream else "tcp"
                    parser.add_argument(
                        name + 'stream', metavar= name + "_" + protocol + "stream",
                        action=filterAction,
                        # dest= prefix + 
                        type=StreamId,
                        help= protocol + '.stream wireshark id')


            if bitfield & PreprocessingActions.Merge:
                protocol = "mptcp" if bitfield & PreprocessingActions.MergeMpTcp else "tcp"
                _pcap(df_name+"1")
                _pcap(df_name+"2",
                    filterAction=partial(MergePcaps, 
                        name=df_name,
                        # name1=df_name + "1", name2=df_name + "2",
                    protocol=protocol),
                )

                # hidden
                # action is triggered only when meet the parameter
                # merge_pcap = parser.add_argument("--" + name + "_protocol",
                #     action=partial(MergePcaps, prefix=name, protocol=protocol), 
                #     help=argparse.SUPPRESS)
                # merge_pcap.default = "TEST"
            else:
                # print("PreprocessingActions.Merge:")
                # TODO pas forcement
                filterClass = FilterStream 
                _pcap(df_name, pcapAction=LoadSinglePcap, 
                    filterAction=retain_stream(df_name, 
                    mptcp = bool(bitfield & PreprocessingActions.FilterMpTcpStream))
                )

            if bitfield & PreprocessingActions.FilterDestination or direction :
                # this one is full of tricks: we want the object to be of the Enum type
                # but we want to display the user readable version
                # so we subclass list to convert the Enum to str value first.
                # TODO setup our own custom actions to get rid of our hacks
                parser.add_argument(
                    '--dest', metavar="destination", dest=df_name + "destinations",
                    # see preprocess functions to see how destinations is handled when empty
                    default=list(ConnectionRoles),
                    # TODO check how it works
                    action=partial(AppendDestination, df_name),
                    # action="append",
                    choices=CustomConnectionRolesChoices([e.name for e in ConnectionRoles]),
                    # type parameter is a function/callable
                    type=lambda x: ConnectionRoles.from_string(x),
                    help='Filter flows according to their direction'
                    '(towards the client or the server)'
                    'Depends on mptcpstream')


            # TODO add as an action
            if skip_subflows:
                parser.add_argument(
                    '--skip', dest=df_name + "skipped_subflows", type=StreamId,
                    action=exclude_stream(df_name, mptcp=False),
                    default=[],
                    help=("You can type here the tcp.stream of a subflow "
                        "not to take into account (because"
                        "it was filtered by iptables or else)"))

        return parser


# argparse_completer.ACArgumentParser
class MpTcpAnalyzerParser(argparse_completer.ACArgumentParser):

    # def _parse_known_args(self, arg_strings, namespace):
    def parse_known_args(self, args=None, namespace=None):
        """
        override it just to postprocess arguments
        """
        res = super().parse_known_args(args, namespace)

        # TODO call filter_dataframe ?
        # for name, df in res.dataframes.items():
        #     print

        print("Hey jude")
        return res

