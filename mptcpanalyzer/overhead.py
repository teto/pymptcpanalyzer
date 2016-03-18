#!/usr/bin/python3.5
# attempt to do some monkey patching
from mptcpanalyzer.command import Command

from enum import Enum

class OptionSize(Enum):
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


class MpTcpOverhead(Command):
    """

    """

    def __init__(self):
        pass

    def _dss_size(with_ack : bool, with_mapping : bool) -> int:
        """
        """
        size = 

    def _overhead_const (total_nb_of_subflows : int):
        """
        Returns constant overhead for a connection

        Mp_CAPABLE + MP_DSSfinal + sum of MP_JOIN
        """
        return OptionSize.Capable + total_nb_of_subflows * 

    def do(self, data):
        print("hello world")

    def help(self):
        """
        """
        print("Allow to generate stats")

    def complete(self, text, line, begidx, endidx):
        """
        """
