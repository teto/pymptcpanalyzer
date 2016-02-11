#!/usr/bin/env python
#  vim: set et fdm=manual fenc= ff=unix sts=4 sw=4 ts=8 : 
import configparser
import os
import logging

log = logging.getLogger("mptcpanalyzer")

class MpTcpAnalyzerConfig(configparser.ConfigParser):
    """
    Thin wrapper around configparser to set up default values
    """

    def __init__(self, filename=""):
        """
        Respect XDG specifications
        """
        super().__init__(allow_no_value=False)

        # ensure defaults for mandatory parameters
        self.read_dict({
            "DEFAULTSECT": { "tshark": "tshark"}
            })

        if not filename:
            filename = os.getenv("XDG_DEFAULT_HOME", "~/.config")
            filename = os.path.join(filename, "mptcpanalyzer", "config")

        if os.path.exists(filename):
             self.read(filename)

