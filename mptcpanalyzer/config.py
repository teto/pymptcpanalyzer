#!/usr/bin/env python
#  vim: set et fdm=manual fenc= ff=unix sts=4 sw=4 ts=8 :
import configparser
import os
import logging

log = logging.getLogger("mptcpanalyzer")

"""
Global config initialized in cli.py.
Singleton-like
"""
# config = None # type: MpTcpAnalyzerConfig


class MpTcpAnalyzerConfig(configparser.ConfigParser):
    """
    Thin wrapper around configparser to set up default values

    By default, mptcpanalyzer will try to load the config file
    first in $XDG_CACHE_HOME/mptcpanalyzer/config, then in
    $HOME/.config/mptcpanalyzer/config.

    Example:

    .. literalinclude:: /../../../examples/config

    """

    def __init__(self, filename: str = None) -> None:
        """
        If filename is set, forcefully uses that file, other than that try
        to read from $XDG_CONFIG_HOME/mptcpanalyzer/config
        Respect XDG specifications
        """
        super().__init__(allow_no_value=False)

        # possible list of config filenames
        filenames = []

        cache_filename = os.path.join(
            os.getenv("XDG_CACHE_HOME", os.path.expanduser("~/.cache")),
            "mptcpanalyzer"
        )

        # ensure defaults for mandatory parameters
        self.read_dict({
            "mptcpanalyzer": {
                "tshark_binary": "tshark",
                "delimiter": "|",
                "cache": cache_filename,
                "wireshark_profile": "",
                "style0": "",
                "style1": "",
                "style2": "",
                "style3": "",
            }
        })

        if filename is None:
            xdg_config = os.getenv("XDG_CONFIG_HOME", "~/.config")
            xdg_config = os.path.join(xdg_config, "mptcpanalyzer", "config")
            filenames.append(xdg_config)
        elif filename:
            log.info("Config file set to %s" % filename)
            filenames = [filename]

        # if os.path.exists(filename):
        loaded_from = self.read(filenames)
        if filename and filename not in loaded_from:
            raise ValueError("Could not load the specified configuration")
        log.info("Configuration loaded from %s", loaded_from)

    @property
    def cachedir(self):
        return self["mptcpanalyzer"]["cache"]
