# -*- coding: utf-8 -*-
import logging
from enum import Enum, IntEnum, Flag, IntFlag, auto
from .config import MpTcpAnalyzerConfig
from .cache import Cache
from .tshark import TsharkConfig
import collections
import numpy as np
import functools
import argparse
import enum
# import ast
from cmd2 import argparse_completer
from colorama import Fore, Back
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


class TcpFlags(IntFlag):
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

class TcpStreamId(int):
    pass

class MpTcpStreamId(int):
    pass

# Keep it as Enum so that it gets serialized as a string in the CSV
# @register_extension_dtype
    # must be implemented
    # * type
    # * name
    # * construct_from_string
class ConnectionRoles(IntEnum):
    """
    Used to filter datasets and keep packets flowing in only one direction !
    Parser should accept --destination Client --destination Server if you want both.
    """
    Client = auto()
    Server = auto()

    # def __str__(self):
    #     # Note that defining __str__ is required to get ArgumentParser's help output to include
    #     # the human readable (values) of Color
    #     return self.name

    # @staticmethod
    def from_string(s):
        try:
            return ConnectionRoles[s]
        except KeyError:
            raise ValueError()

    def __next__(self):
        if self.value == 0:
            return ConnectionRoles.Server
        else:
            return ConnectionRoles.Client


# TODO create an action instead
# TODO should be able to do without
class CustomConnectionRolesChoices(list):
    def __contains__(self, other):
        # print("%r", other)
        return super().__contains__(other.name)

# workaround argparse choices limitations
DestinationChoice = CustomConnectionRolesChoices([e.name for e in ConnectionRoles])




# merged, name
# DataframeDescriptor = NamedTuple()

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


class DataframeCharacteristic(enum.Flag):
    Mptcp      = enum.auto()

class PreprocessingActions(enum.Flag):
    """
    What to do with pcaps on the command line
    """
    DoNothing                = enum.auto()
    # always preloaded ?
    Preload                  = enum.auto()
    SkipSubflows             = enum.auto()
    FilterTcpStream          = enum.auto()
    FilterMpTcpStream        = enum.auto()
    FilterStream        = FilterMpTcpStream | FilterTcpStream
    MergeMpTcp               = enum.auto()
    MergeTcp                 = enum.auto()
    Merge                    = MergeMpTcp | MergeTcp
    FilterDestination        = enum.auto()
    # FilterStream             = FilterMpTcpStream | FilterTcpStream


# logging.DEBUG = 10 so we need to be lower
TRACE = 5

logging.addLevelName(TRACE, 'TRACE')

class MpTcpMissingPcap(MpTcpException):
    pass

__all__ = [
    'List',
    'RECEIVER_SUFFIX'
]

