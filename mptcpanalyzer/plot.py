#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import sys
import os
import tempfile
import matplotlib
import logging
# from plots import *
# import mptcpanalyzer.sqlite_helpers

# from mptcpanalyzer.sqlite_helpers import MpTcpDatabase
import abc

import six


log = logging.getLogger("mptcpanalyzer")

def gen_ip_filter(mptcpstream, ipsrc=None, ipdst=None):
    """
    filter dataset from ips
    filter to only account for one direction (departure or arrival)
    """
    # if mptcpstream:
    query = " mptcpstream == %d " % mptcpstream

    if ipsrc:
        query += " and ("
        query_ipdst = map( lambda x: "ipsrc == '%s'" % x, ipsrc)
        query += ' or '.join(query_ipdst)
        query += ")"

    if ipdst:
        query += " and ("
        query_ipdst = map( lambda x: "ipdst == '%s'" % x, ipdst)
        query += ' or '.join(query_ipdst)
        query += ")"

    return query

@six.add_metaclass(abc.ABCMeta)
class Plot:
    """
    See http://docs.openstack.org/developer/stevedore/tutorial/creating_plugins.html

    This relies on Pandas + matplotlib to generate plots
    There is a bug in Pandas that prevents from plotting raw DSNs as uint64 see
    https://github.com/pydata/pandas/issues/11440
    """
    # @staticmethod
    def default_parser(self):
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
        parser.add_argument('-o', '--out', action="store", nargs="?", default="output.png", help='Name of the output file')
        parser.add_argument('--display', action="store_true", help='will display the generated plot')
# Move to matplotlib

        return parser

    @staticmethod
    def filter_ds(data, **kwargs):
        query = gen_ip_filter(**kwargs)
        # dat = data[data.mptcpstream == args.mptcpstream]
        log.debug("Running query %s" % query)
        dat = data.query(query)
        return dat

    # *args
    @abc.abstractmethod
    def _generate_plot(self, data, args, **kwargs):
        pass

#display : bool, savefig : bool, *
    def plot(self, data, args, **kwargs):
        """
        Accepts 
        """
        
        self._generate_plot(data, args, **kwargs)

        if args.display:
            self.display(args.out)

    def savefigure(self):
        raise NotImplementedError()

    # @staticmethod
    def display(self, filename):

        """
        TODO command should be in the config
        """
        cmd = "xdg-open %s" % (filename)
        print(cmd)
        os.system(cmd)

    def get_client_uniflow_filename(self, id):
        # os.join.path()
        return self.output_folder + "/" + "client_" + str(id) + ".csv"    

    def get_server_uniflow_filename(self, id):
        # os.join.path()
        return self.output_folder + "/" + "server_" + str(id) + ".csv"

    def get_subflow_filename(self, id):
        # os.join.path()
        return self.output_folder + "/" + "subflow_" + str(id) + ".csv"


# class PandaPlot(Plot):
#     def savefig()
#         args.out = os.path.join(os.getcwd(), args.out)
#         print("Saving into %s" % (args.out))
#         fig.savefig(args.out)

class Matplotlib(Plot):

    def default_parser(self):
        parser = super().default_parser()
        parser.add_argument('--style', dest="styles", action="append", default=[], help='List matplotlib styles')
        return parser

    def plot(self, data, args, **kwargs):
        """
        """
        # with plt.style.context(args.styles):
        # setup styles if any
        log.debug("Using styles: %s" % args.styles)
        matplotlib.pyplot.style.use(args.styles)
        fig = self._generate_plot(data, args, **kwargs)

        if args.out:
            self.savefig(fig,args.out)

        if args.display:
            # TODO show it from fig
            self.display(args.out)

    @staticmethod
    def savefig(fig, filename):

        filename = os.path.join(os.getcwd(), filename)
        # logger.info
        print("Saving into %s" % (filename))
        fig.savefig(filename)

