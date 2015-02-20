#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import sys
import os
import tempfile

# import mptcpanalyzer.sqlite_helpers

from mptcpanalyzer.sqlite_helpers import MpTcpDatabase

class Plot:
    """
    Output folder
    """

    # output
    parser = None
    db = None
    output_folder = None
    #outfile,

    def __init__(self, *args):

        # self.output_folder = tempfile.TemporaryDirectory()
        self.output_folder = tempfile.mkdtemp()
        self.output_folder = "out"

        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots'
        )
        # input_db, outfile,
        parser.add_argument("sql_db", type=str, action="store", help="file")
        parser.add_argument('--out', action="store", default="", help='Name of the output folder, if default, a random one is generated')

        self._complete_parser(parser)
        self.parser = parser

        args = self.parser.parse_args()
        print(args, ...)
        self.db = MpTcpDatabase(args.sql_db)

        # TODO creer un parser de base, appeler compelte parser ?
        self.init(args)

    def init(self, args):
        """
        Args returned by the parser
        Override this one instead of __init__
        """
        pass

    def _complete_parser(self, parser):
        """
        sds
        """
        pass

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
