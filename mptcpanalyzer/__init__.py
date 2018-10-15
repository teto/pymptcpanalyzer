# -*- coding: utf-8 -*-
import logging
from enum import Enum, IntEnum, Flag, auto
from .config import MpTcpAnalyzerConfig
from .cache import Cache
import collections
import numpy as np
import enum
# import ast
from cmd2 import argparse_completer
from typing import Iterable, List, Dict
import ast

__CONFIG__ = None  # type: 'MpTcpAnalyzerConfig'
__CACHE__ = None  # type: 'Cache'

"""
Used when dealing with the merge of dataframes
"""
SENDER_SUFFIX  = "" # "_sender"
RECEIVER_SUFFIX= "_receiver"

# we can't let it empty else we can't rename fields
HOST1_SUFFIX  = "_h1"
HOST2_SUFFIX  = "_h2"

def suffix_fields(suffix, fields):

    f = lambda x: x + suffix
    # if isinstance(fields, collections.Iterable):
    if isinstance(fields, str):
        return f(fields)

    b = list(map(f, fields))
    return b

def _first(fields):
    return suffix_fields(HOST1_SUFFIX, fields)

def _second(fields):
    return suffix_fields(HOST2_SUFFIX, fields)

def _sender(fields):
    return suffix_fields(SENDER_SUFFIX, fields)

def _receiver(fields):
    return suffix_fields(RECEIVER_SUFFIX, fields)


def get_cache() -> Cache:
    global __CACHE__  # add this line!
    # print("config STATE=", __CONFIG__)
    if __CACHE__ is None:  # see notes below; explicit test for None
        raise RuntimeError("Cache has not been set yet.")
    return __CACHE__


def get_config() -> MpTcpAnalyzerConfig:
    global __CONFIG__  # add this line!
    if __CONFIG__ is None:  # see notes below; explicit test for None
        raise RuntimeError("Config has not been set yet.")
    return __CONFIG__

# """
# The number of rows in the CSV file assigned to metadata (mptcpanalyzer version,
# tshark options etc...)
# """
# METADATA_ROWS = 2


# def _load_list(x, field="pass a field to debug"):
#     """
#     Loads x of the form "1,2,5" or None
#     for instance functools.partial(_convert_to_list, field="reinjectionOf"),
#     returns np.nan instead of [] to allow for faster filtering
#     """
#     # pandas error message are not the best to understand why the convert failed
#     # so we use this instead of lambda for debug reasons
#     print("converting field %s with value %r" % (field, x))
#     res = list(map(int, x.split(','))) if (x is not None and x != '') else np.nan
#     return res

# doesn't seem to work
# sometimes it will create a tuple only if there are several elements
def _load_list(x, field="set field to debug"):
    """
    Contrary to _convert_to_list
    """
    if x is None or len(x) == 0:
        return np.nan

    if x[0] != "[":
        x = "[" + x + "]"
    #if (x is not None and x != '') else np.nan
    res = ast.literal_eval(x) 

    # print("res", res)
    return res


class TcpFlags(Flag):
    NONE = 0
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32
    ECE = 64
    CWR = 128

class MpTcpOptions(IntEnum):
    """
    Real value of the options.
    Useful to filter the dataframe
    """

    MP_CAPABLE = 0
    MP_JOIN    = 1
    MP_DSS =  2
    MP_ADD_ADDR =  3
    MP_REMOVE_ADDR = 4 
    MP_PRIO = 5
    MP_FAIL = 6
    MP_FASTCLOSE = 7

# Keep it as Enum so that it gets serialized as a string in the CSV
class ConnectionRoles(Enum):
    """
    Used to filter datasets and keep packets flowing in only one direction !
    Parser should accept --destination Client --destination Server if you want both.

    TODO: convert back to enum, that was done for bad reasons
    """
    Client = auto()
    Server = auto()

    def __str__(self):
        # Note that defining __str__ is required to get ArgumentParser's help output to include the human readable (values) of Color
        return self.name

    @staticmethod
    def from_string(s):
        try:
            return ConnectionRoles[s]
        except KeyError:
            raise ValueError()

    def __next__(self):
        # 
        if self.value == 0:
            return ConnectionRoles.Server
        else:
            return ConnectionRoles.Client

class CustomConnectionRolesChoices(list):
    def __contains__(self, other):
        # print("%r", other)
        return super().__contains__(other.name)


# workaround argparse choices limitations
DestinationChoice = CustomConnectionRolesChoices([e.name for e in ConnectionRoles])

def reverse_destination(dest: ConnectionRoles):

    if dest == ConnectionRoles.Client:
        return ConnectionRoles.Server
    elif dest == ConnectionRoles.Server:
        return ConnectionRoles.Client

    raise Exception()
    # else:
    #     # or assert .
    #     return ConnectionRoles.Both

class MpTcpException(Exception):
    """
    Exceptions thrown by this module should inherit this in order to let the cli
    filter exceptions
    """
    pass


class PreprocessingActions(enum.Flag):
    """
    What to do with pcaps on the command line
    """
    DoNothing                = enum.auto()
    Preload                  = enum.auto()
    FilterTcpStream          = enum.auto()
    FilterMpTcpStream        = enum.auto()
    FilterStream             = FilterMpTcpStream | FilterTcpStream


def gen_bicap_parser(protocol, dest=False):
    """
    protocol in ["mptcp", "tcp"]
    """
    action = PreprocessingActions.Preload | (PreprocessingActions.FilterMpTcpStream if protocol == "mptcp" else PreprocessingActions.FilterTcpStream)
    input_pcaps = {
        "pcap1": action,
        "pcap2": action,
    }
    return gen_pcap_parser(input_pcaps=input_pcaps, direction=dest)

def gen_pcap_parser(
        input_pcaps: Dict[str, PreprocessingActions],
        direction: bool = False,
        parents=[],
        skip_subflows: bool = True,
        # dst_host: bool=False,
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

        for name, bitfield in input_pcaps.items():

            load_pcap = parser.add_argument(name, action="store", type=str, help='Pcap file')
            setattr(load_pcap, argparse_completer.ACTION_ARG_CHOICES,
                ('path_complete', [False, False]))
            parser.add_argument("--clock-offset" + name, action="store", type=int,
                help='Offset compared to epoch (in nanoseconds)')

            if bitfield | PreprocessingActions.FilterStream:
                # difficult to change the varname here => change it everywhere
                protocol = ""
                if bitfield & PreprocessingActions.FilterMpTcpStream:
                    protocol = "mptcp"
                elif bitfield & PreprocessingActions.FilterTcpStream:
                    protocol = "tcp"
                parser.add_argument(
                    name + 'stream', metavar= protocol + "stream", action="store", type=int,
                    help= protocol + '.stream wireshark id')

        if direction:
            # this one is full of tricks: we want the object to be of the Enum type
            # but we want to display the user readable version
            # so we subclass list to convert the Enum to str value first.
            parser.add_argument(
                '--dest', metavar="destination", dest="destinations",
                # see preprocess functions to see how destinations is handled when empty
                default=None,
                action="append",
                choices=CustomConnectionRolesChoices([e.name for e in ConnectionRoles]),
                # type parameter is a function/callable
                type=lambda x: ConnectionRoles.from_string(x),
                help='Filter flows according to their direction'
                '(towards the client or the server)'
                'Depends on mptcpstream')

        # TODO add as an action
        if protocol == "mptcp" and skip_subflows:
            parser.add_argument(
                '--skip', dest="skipped_subflows", type=int,
                action="append", default=[],
                help=("You can type here the tcp.stream of a subflow "
                    "not to take into account (because"
                    "it was filtered by iptables or else)"))

        # parser.add_argument('-o', '--out', action="store", default=None,
        #     help='Name of the output plot')
        # parser.add_argument('--display', action="store_true",
        #     help='will display the generated plot (use xdg-open by default)')
        # parser.add_argument('--title', action="store", type=str,
        #     help='Overrides the default plot title')
        # parser.add_argument('--primary', action="store_true",
        #     help="Copy to X clipboard, requires `xsel` to be installed")
        return parser

# def gen_bigroup_parser(protocol, dest=False):
#     """
#     protocol in ["mptcp", "tcp"]
#     """
#     parser = argparse_completer.ACArgumentParser(
#         description="""
#         Empty description, please provide one
#         """
#     )
#     subparsers = parser.add_subparsers(dest="protocol",
#             title="Subparsers", help='Choose protocol help',)

#     subparsers.required = True  # type: ignore

#     load_pcap1 = parser.add_argument("pcap1", type=str, help="Capture file 1")
#     load_pcap2 = parser.add_argument("pcap2", type=str, help="Capture file 2")
#     for action in [load_pcap1, load_pcap2]:
#         setattr(action, argparse_completer.ACTION_ARG_CHOICES, ('path_complete', [False, False]))
#     parser.add_argument("stream", type=int, help=protocol + ".stream wireshark id")
#     parser.add_argument("stream2", type=int, help=protocol + "stream wireshark id")

#     # TODO make it mandatory or not
#     if dest:
#         dest_action = parser.add_argument(
#             '--destination',
#             action="store",
#             choices=DestinationChoice,
#             type=lambda x: mp.ConnectionRoles[x],
#             # default=[ mp.ConnectionRoles.Server, mp.ConnectionRoles.Client ],
#             help='Filter flows according to their direction'
#             '(towards the client or the server)'
#             'Depends on mptcpstream'
#         )
#         # tag the action objects with completion providers. This can be a collection or a callable
#         # setattr(dest_action, argparse_completer.ACTION_ARG_CHOICES, static_list_directors)
#     return parser

class MpTcpMissingPcap(MpTcpException):
    pass

__all__ = [
    'List',
    'RECEIVER_SUFFIX'
]

