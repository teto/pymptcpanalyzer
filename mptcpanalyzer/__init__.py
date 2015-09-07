#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pkgutil import extend_path

# from mptcpanalyzer.core import get_basename
import logging
import os
from . import plot
from .core import load_fields_to_export_from_file

__path__ = extend_path(__path__, __name__)


# h = logging.FileHandler(".mptcpanalyzer-" + str(os.getpid()), delay=True)
# TODO let final script set the handler
h = logging.FileHandler("mptcpanalyzer.log", delay=False)

logger = logging.getLogger(__name__)
logger.addHandler(h)
logger.setLevel(logging.CRITICAL)






# status.run()
# dict to create distinct and understandable csv/sql keys
# print(__path__[0])
# TODO this sounds like a bit of a hack
fields_dict = load_fields_to_export_from_file(__path__[0] + "/mptcp_fields.json")
# {
#     "packetid": "frame.number",
#     "time": "frame.time",


# TODO move away
# plotsDir = "plots"
table_name = "connections"

__all__ = [
    # "Status",
    # "Module", "IntervalModule",
    # "SettingsBase",
    # "formatp",
    "fields_dict",
    "table_name",
    "load_fields_to_export_from_file",
    # "get_basename",
    # fields_to_export,
]
