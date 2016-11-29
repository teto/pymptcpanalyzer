from unittest import TestCase
import unittest

import mptcpanalyzer as mp
from mptcpanalyzer.cli import MpTcpAnalyzer, main
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.connection import MpTcpConnection
import mptcpanalyzer.data as data
import mptcpanalyzer.plots as plots
import pandas as pd
from stevedore.extension import Extension
import tempfile
import shlex
import shutil
import logging
import os
import pathlib

mptcp_pcap = "examples/iperf-mptcp-0-0.pcap"
mptcp_pcap = os.path.abspath("examples/iperf-mptcp-0-0.pcap")
# should be the same as in 
# plot_output = ""

config_file = os.path.abspath("tests/test_config.ini")

loglevel = logging.DEBUG



class OwdTest(TestCase):
    pass

