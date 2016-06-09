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

    def __init__(self, filename: str = None):
        """
        If filename is set, forcefully uses that file, other than that try
        to read from $XDG_DEFAULT_HOME/mptcpanalyzer/config
        Respect XDG specifications
        """
        super().__init__(allow_no_value=False)

        # possible list of config filenames
        filenames = []

        # ensure defaults for mandatory parameters
        self.read_dict({
            "DEFAULT": { 
                "tshark_binary": "tshark",
                "delimiter": "|",
                "cache": os.path.join(os.getenv("XDG_CACHE_HOME", os.path.expanduser("~/.cache/")), "mptcpanalyzer"),
                "wireshark_profile": "",
                "style0": "",
                "style1": "",
                "style2": "",
                "style3": "",
                }
            })

        if not filename:
            xdg_config = os.getenv("XDG_CONFIG_HOME", "~/.config")
            xdg_config = os.path.join(xdg_config, "mptcpanalyzer", "config")
            filenames.append(xdg_config)

        if filename:
            log.info("Config file set to %s" % filename)
            filenames = [filename]
        

        # if os.path.exists(filename):
        loaded_from = self.read(filenames)
        if filename and filename not in loaded_from:
            raise ValueError("Could not load the specified configuration")
        log.info("Configuration loaded from %s", loaded_from)
        # else:
        #     log.debug("Could not find config file %s" % filename)

