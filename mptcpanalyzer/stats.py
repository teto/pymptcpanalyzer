#:/usr/bin/env python3
from mptcpanalyzer.command import Command

from enum import Enum, IntEnum
import argparse
import shlex
import json

def MpTcpOptions(Enum):
    NRSACK
    SACK
    DelayedAck


class DoStats(Command):

    def __init__(self):
        pass

    def do(self, data):
        print("hello world")

    def rto ():
        pass

    def help(self):
        """
        """
        print("Allow to generate stats")

        parser = Argument.argparse (help="Allows to compute stats")
        parser.add_argument("topologie", action="store", help="File to load topology from")
        parser.add_argument("topologie", action="store", help="File to load topology from")
        args = parser.parse_args( shlex.split(args))

    def complete(self, text, line, begidx, endidx):
        """
        """
