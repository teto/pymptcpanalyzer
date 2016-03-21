#:/usr/bin/env python3
from mptcpanalyzer.command import Command

from enum import Enum, IntEnum
import argparse
import shlex
import json

class MpTcpOptions(Enum):
    NRSACK = 0
    SACK   = 1
    DelayedAck = 2


class DoStats(Command):

    def __init__(self):
        pass

    def do(self, data):
        print("hello world")
        parser = argparse.ArgumentParser(description="Allows to compute stats")
        parser.add_argument("topology", action="store", help="File to load topology from")
        # parser.add_argument("topologie", action="store", help="File to load topology from")
        args = parser.parse_args( shlex.split(data))
        print("topology=", args.topology ) 
        with open(args.topology) as f:
            j = json.load(f)
            print("Number of subflows=%d" % len(j["subflows"]))

            for s in j["subflows"]:
                print("fowd=%d" % s["fowd"])
    def rto ():
        pass

    def help(self):
        """
        """
        print("Allow to generate stats")


    def complete(self, text, line, begidx, endidx):
        """
        """
