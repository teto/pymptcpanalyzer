#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import sys
import os
import tempfile
# from plots import *
# import mptcpanalyzer.sqlite_helpers

# from mptcpanalyzer.sqlite_helpers import MpTcpDatabase

class Plot:
    """
    This relies on Pandas + matplotlib to generate plots
    There is a bug in Pandas that prevents from plotting raw DSNs as uint64 see
    https://github.com/pydata/pandas/issues/11440
    """
    @staticmethod
    def default_parser():
        """
        Generate parser with commonu arguments
        """
        # parser = argparse.ArgumentParser(
        #     description='Generate MPTCP stats & plots'
        # )
        parser = argparse.ArgumentParser(description='Generate MPTCP stats & plots')
        # parse
        # parser.add_argument('field', action="store", choices=plot_types, help='Field to draw (see mptcp_fields.json)')
        parser.add_argument('mptcpstream', action="store", type=int, help='mptcp.stream id')
        parser.add_argument('out', action="store", nargs="?", default="output.png", help='Name of the output file')
        parser.add_argument('--display', action="store_true", help='will display the generated plot')

        # parser.add_argument("mptcp_stream", action="store", type=int, help="identifier of the MPTCP stream")
        # parser.add_argument('--out', action="store", default="", help='Name of the output folder, if default, a random one is generated')
        return parser

    # *args
    def plot(self, data,):
        raise NotImplementedError()

    @staticmethod
    def get_available_plots(path):
        """
        Folders to look to
        """
        # easy way = plot_types = glob.glob("plots/*.py")
        # files = files if isinstance(files, list) else ['plots/dsn']
    # def get_available_plots(self):
        from .plots import dsn
        # import pkgutil
        # import importlib
        # /home/teto/mptcpanalyzer/mptcpanalyzer/plots/
        # packages = pkgutil.walk_packages(path)
        # print(list(packages))
        # for importer, name, is_package in packages:
        #     mod = importlib.import_module(name)
        # for f in files:
        #     import files
# def all_subclasses(cls):
        # plot_types[args.plot_type]
        return Plot.__subclasses__() 
        # to make it recursive
        # + [g for s in Plot.__subclasses__()
        #                        for g in all_subclasses(s)]
    # plot_types = dict((x.__name__, x) for x in Plot.get_available_plots())
    # print("available plots:", plot_types)

    def get_client_uniflow_filename(self, id):
        # os.join.path()
        return self.output_folder + "/" + "client_" + str(id) + ".csv"    

    def get_server_uniflow_filename(self, id):
        # os.join.path()
        return self.output_folder + "/" + "server_" + str(id) + ".csv"

    def get_subflow_filename(self, id):
        # os.join.path()
        return self.output_folder + "/" + "subflow_" + str(id) + ".csv"
