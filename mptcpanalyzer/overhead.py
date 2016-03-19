#!/usr/bin/python3.5
# attempt to do some monkey patching
from mptcpanalyzer.command import Command

from enum import Enum, IntEnum
import argparse
import shlex
import json

class OptionSize(IntEnum):
    """
    Size in byte of MPTCP options
    """
    # 12 + 12 + 24
    Capable = 48
    # should be 12 + 16 + 24
    Join = 52
    FastClose = 12
    Fail = 12
    # 
    AddAddr4 = 10
    AddAddr6 = 22
    
    # 3 + n * 1 ?
    # RmAddr 

class DssAck(IntEnum):
    None = 0
    SimpleAck = 4
    ExtendedAck = 8

class DssMapping(IntEnum):
    None = 4
    Simple = 8
    Extended = 12

class MpTcpOverhead(Command):
    """

    """

    def __init__(self):
        pass

    def _dss_size(ack : DssAck, mapping : DssMapping, with_checksum=False : bool) -> int:
        """
        """
        size = 4
        size += ack.value
        size += mapping.value
        size += 2 if checksum else 0
        return size

    def _overhead_const (total_nb_of_subflows : int):
        """
        Returns constant overhead for a connection

        Mp_CAPABLE + MP_DSSfinal + sum of MP_JOIN
        """
        return OptionSize.Capable.value + total_nb_of_subflows * OptionSize.Join.value

    def do(self, data):
        parser = Argument.argparse (help="")
        parser.add_argument("topologie", action="store", help="File to load topology from")
        args = parser.parse_args( shlex.split(args))
        print("hello world")
        json.load()
# TODO this should be a plot rather than a command

    def help(self):
        """
        """
        print("Allow to generate stats")

    def complete(self, text, line, begidx, endidx):
        """
        """
