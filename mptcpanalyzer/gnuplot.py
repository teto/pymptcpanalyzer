#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import sys
import os
import tempfile

# import mptcpanalyzer.sqlite_helpers

# from mptcpanalyzer.sqlite_helpers import MpTcpDatabase

class Plot:
    """
    Output folder
    """

    # output
    parser = None
    db = None
    output_folder = None
    #outfile,

    def __init__(self, ):
        # *args, **kwargs
        """
        @param db MpTcpDatabase
        args arguments not parsed by argparse
        should accept the database
        """
        # self.output_folder = tempfile.TemporaryDirectory()
        self.output_folder = tempfile.mkdtemp()
        self.output_folder = "out"

        self.db = db

        self.init(args)

    def init(self, *args, **kwargs):
        """
        Args returned by the parser
        Override this one instead of __init__
        """
        pass

    @staticmethod
    def get_parser():
        return __class__.default_parser()

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
        parser.add_argument('field', action="store", choices=plot_types, help='Field to draw (see mptcp_fields.json)')
        parser.add_argument('mptcpstream', action="store", type=int, help='mptcp.stream id')
        parser.add_argument('out', action="store", nargs="?", default="output.png", help='Name of the output file')
        parser.add_argument('--display', action="store_true", help='will display the generated plot')

        # parser.add_argument("mptcp_stream", action="store", type=int, help="identifier of the MPTCP stream")
        # parser.add_argument('--out', action="store", default="", help='Name of the output folder, if default, a random one is generated')
        return parser

    @staticmethod
    def get_available_plots(folders=None):
        """
        Folders to look to
        """
    # def get_available_plots(self):
# def all_subclasses(cls):
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

    # def start(self):
    #     self.parser.parse(sys.argv)
    def generate(self):
        raise NotImplementedError()

    # TODO remove dependancy towards gnuplot, we should be backend independant
    def _call_gnuplot(self, gnuplot_script, output, **kwargs):
        """
        Run gnuplot

        kwargs are parsed and passed to 
        """
        def gen(**kwargs):
            ret = ""
            for key, value in kwargs.items():
                ret += "%s='%s';" % (key, value,)
            return ret

        args = gen(**kwargs)

        # en fait c plutot un input_folder pour gnuplot ?
        args += "output_folder='%s';" % self.output_folder
        args += "output='%s';" % output

        print("args:", args)

        # logger.info("Dataset saved into file %s" % generated_data_filename)
        # passer par defaut output folder
        cmd = "gnuplot -e \"{args}\" {plot}".format(
            # datafile=generated_data_filename,
            args=args,
            plot=gnuplot_script,
        )
        print("Launching command \n", cmd)
        os.system(cmd)
    # def get_meta_filename():
    #     pass

    # def get_subflow_filename(self, id):
    #     pass
