# -*- coding: utf-8 -*-
import logging
from enum import Enum, IntEnum, Flag, auto
from .config import MpTcpAnalyzerConfig
from .cache import Cache
import collections
import numpy as np
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


def _load_list(x, field="pass a field to debug"):
    """
    Loads x of the form "1,2,5" or None
    for instance functools.partial(_convert_to_list, field="reinjectionOf"),
    returns np.nan instead of [] to allow for faster filtering
    """
    # pandas error message are not the best to understand why the convert failed
    # so we use this instead of lambda for debug reasons
    # print("converting field %s with value %r" % (field, x))
    res = list(map(int, x.split(','))) if (x is not None and x != '') else np.nan
    return res

# doesn't seem to work
# sometimes it will create a tuple only if there are several elements
# def _load_list(x, field="set field to debug"):
#     """
#     Contrary to _convert_to_list
#     """
#     res = ast.literal_eval(x) if (x is not None and x != '') else np.nan

#     # print("res", res)
#     return res


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

# hopefully mypy will work with IntEnum's too
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


class MpTcpMissingPcap(MpTcpException):
    pass

__all__ = [
        'List',
        'RECEIVER_SUFFIX'
        ]

