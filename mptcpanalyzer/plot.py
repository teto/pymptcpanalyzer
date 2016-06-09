#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import sys
import os
import tempfile
import matplotlib
import matplotlib.pyplot as plt
import logging
import mptcpanalyzer as mp
from enum import Enum, IntEnum

import abc

import six



class Destination(Enum):
    """
    Used to filter datasets
    """
    Client = "client"
    Server = "server"
    Both = "Both"

log = logging.getLogger("mptcpanalyzer")

def gen_ip_filter(mptcpstream, ipsrc=None, ipdst=None):
    """
    filter mainset from ips
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
    https://github.com/pymain/pandas/issues/11440
    """

    def __init__(self, title : str = None, *args, **kwargs):
        #accept_preload : bool, filter_destination):
        """
        TODO pass a boolean to know if main.data should be preloaded or not
        """
        self.title = title
        # self.accept_preload = accept_preload

    # @staticmethod
    def default_parser(self, mptcpstream: bool = False, direction: bool = False, dst_host : bool=False):
        """
        Generate parser with commonu arguments
        """
        parser = argparse.ArgumentParser(description='Generate MPTCP stats & plots')
        if mptcpstream:
            parser.add_argument('mptcpstream', action="store", type=int, help='mptcp.stream id')

        if direction:
            parser.add_argument('direction', action="store", choices=mp.flow_directions.keys(), 
                    help='Filter flows according to their direction (towards the client or the server)')
        if dst_host:
            parser.add_argument('ipdst_host', action="store", 
                    help='Filter flows according to the destination hostnames')

        parser.add_argument('-o', '--out', action="store", default="output.png", help='Name of the output file')
        parser.add_argument('--display', action="store_true", help='will display the generated plot')
        parser.add_argument('--title', action="store", help='Override plot title')
        parser.add_argument('--primary', action="store_true", help="Copy to X clipboard, require xsel installed")
        return parser

    # might move to standalone ?
    @staticmethod
    def filter_ds(data,  **kwargs):
        """
        direction = client or server
        """
        # query = gen_ip_filter(**kwargs)
        dat = data
        for field, value in dict(**kwargs).items():
            print("name, value", field)
            query = "{field} == '{value}'".format(field=field,value=value)

        # direction = kwargs.get("direction")
        # if direction:
        #     # dat = data[(data.mptcpstream == args.mptcpstream) & (data.direction == args.direction)]
        #     # dat = main[data.mptcpstream == args.mptcpstream]
        #     query = "direction == %d" % mp.flow_directions[direction]

            log.debug("Running query %s" % query)
            dat = data.query(query)
        return dat

    # *args
    @abc.abstractmethod
    def _generate_plot(self, main, args, **kwargs):
        pass



#display : bool, savefig : bool, *
    def plot(self, main, args, **kwargs):
        """
        Accepts 
        """
        # TODO depending on filters, filter dataset
        self._generate_plot(main, args, **kwargs)

        if args.display:
            self.display(args.out)

    def savefigure(self):
        raise NotImplementedError()

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


class Matplotlib(Plot):
    """
    Relies on matplotlib
    """
    

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def default_parser(self, *args, **kwargs):
        parser = super().default_parser(*args, **kwargs)
        parser.add_argument('--style', dest="styles", action="append", default=[],
                help=("List matplotlib styles, you can specify several styles via several --style items."
                      "The style should be either an absolute path or the name of a style in "
                      "$XDG_CONFIG_HOME/matplotlib/stylelib")
                )
        return parser

    def plot(self, main, args, **kwargs):
        """
        """

        # autofilter dataset if needed
        # for name, val in args.__dict__.items():
        #     if name in get_default_fields():
                #exporter
                # filter_ds()
        # check filetered dataset is not empty 

        # with plt.style.context(args.styles):
        # setup styles if any
        log.debug("Using styles: %s" % args.styles)
        # matplotlib.pyplot.style.use(args.styles)
        # ('dark_background')
        with plt.style.context(args.styles):
            fig = self._generate_plot(main, args, **kwargs)

        self.title = args.title if args.title else self.title
        if self.title:
            fig.suptitle(self.title,  fontsize=12)

        if args.out:
            self.savefig(fig, args.out)
            if args.primary:
                core.copy_to_x(args.out)

        if args.display:
            # TODO show it from fig
            self.display(args.out)

    @staticmethod
    def savefig(fig, filename):

        filename = os.path.join(os.getcwd(), filename)
        # logger.info
        print("Saving into %s" % (filename))
        fig.savefig(filename)

