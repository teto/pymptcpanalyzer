#!/usr/bin/env python
# -*- coding: utf-8 -*-

import mptcpanalyzer.plot as plot
import mptcpanalyzer.core as core
import pandas as pd
import logging
import matplotlib.pyplot as plt
import argparse
import numpy as np

import collections
import glob
import shlex, subprocess

from typing import Callable

log = logging.getLogger(__name__)

# sadly, pandas ~ 0.18 does not support NA for np.int64 types and this files is full of NAs
# hence we cast all fields to floats :'(
# https://github.com/pydata/pandas/issues/2631
ns3_attributes = {
        "Time" : ("time (ns)", pd.datetime),
        "txNext" : ("{type} Tx Next", np.float64),
        "highestSeq" : ("{type} {idx} Highest seq", np.float64),
        "unackSeq" : ("{type} {idx} SND.UNA", np.float64),
        "rxNext": ("RxNext", np.float64),
        "rxAvailable": ("{type} Rx Available", np.float64),
        "rxTotal" : ("{type} rxtotal", np.float64),
        "cwnd": ("{type} {idx} cwnd", np.float64),
        "rWnd": ("RWnd", np.float64),
        "ssThresh": ("{type} SS Thresh", np.float64),
        "state": ("State", str),
        }

prefixes = [
  "meta",
  # "subflow0",
  # "subflow1",
]


def gen_configs(with_meta: bool, gen_conf: Callable[[str], list]) -> list:
  """
  """
  # def gen_tx_config(prefix: str) -> list:
    # return [   Config("meta_TxNext.csv" % prefix, "newNextTxSequence", "Meta Tx Next"),
              # Config("%s_TxUnack.csv" % prefix, "newUnackSequence", "Meta Tx Unack"),
             # ]
  configs = []
  if with_meta:
    configs += gen_conf("meta")

  for i in range(nb_of_subflows):
    configs += gen_conf("subflow%d" % i)

  return configs


class PlotTraceSources(plot.Matplotlib):
    """
    This plugin aims at plotting ns3 *TraceSource* results. As such, it does not 
    rely on pcap files.

    ..warning:: The format for this file is not upstreamed yet

    :Example:

    plot 

    """
    def __init__(self, *args, **kwargs):
        pcaps = [
            # ("pcap", plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterStream),
            # | plot.PreprocessingActions.SkipSubflow
        ]
        super().__init__(input_pcaps=pcaps, *args, **kwargs)

    def default_parser(self, *args, **kwargs):
        """
        This plugin does not need any dataframe
        """
        parser = argparse.ArgumentParser(
            description="unofficial ns3 mptcp plotting tool for TcpTraceHelper generated files")
        parser.add_argument("folder", help="Choose client or server folder")
        parser.add_argument("node", help="Choose node to filter from")
        parser.add_argument("attributes", choices=ns3_attributes,
                nargs="+",
                help="Choose client or server folder")
        # parser.add_argument("--node", "-n", dest="nodes", action="append", default=[0], help="Plot subflows along")
        parser.add_argument("--meta", "-m", action="store_true", default=False,
                help="Plot meta along")
        parser.add_argument("--subflows", "-s", action="store_true", default=False,
                help="Plot subflows along")
        return parser

    def plot(self, df, args, ):
        """
        Plot column "attribute" to "output" file (*.png)
        """
        node = args.node
        attributes = args.attributes
        with_meta = args.meta
        with_subflows = args.subflows

        log.info("Plotting attribute [%s]" % attributes)
        legends = []
        configs = []

        if with_meta:
            log.debug("With meta")
            # pattern type
            configs.append((str(node) + "*meta*.csv", "meta"))

        if with_subflows:
            log.debug("With subflows")
            configs.append((str(node) + "*subflow*.csv", "Subflow"))

        folder = args.folder

        log.info("Loading from [%s] folder" % folder)
        # for node in args.nodes:

        #     if not args.out:
        output = "node{node}{meta}{subflows}_{attr}.png".format(
            node = str(node),
            meta= "_meta" if args.meta else "",
            subflows= "_subflows" if args.subflows else "",
            attr='_'.join(attributes),
            )

        log.info("Output set to %s" % output)

             
        fig = plt.figure (figsize=(8,8))
        axes = fig.gca()

        for pattern, name in configs:

            matches = glob.glob( folder + "/" + pattern)
            if matches is None:
                raise Exception("No meta file found")

            for idx, filename in enumerate(matches):
                print(filename)
                dtypes= core.get_dtypes(ns3_attributes)
                print(dtypes)
                d = pd.read_csv(filename , index_col="Time", dtype=dtypes)
                # d.index = pd.to_timedelta(d.index)
                # print(d.index)
                for attribute in attributes:
                    print( "prefix name=", ns3_attributes[attribute][0] )
                    dat = d[attribute].dropna()
                    print("len before dropping head", len(dat))

                    # HACK to have nice plots else some initial parameters are set to 0 via ns3
                    # and mess up the plot scale
                    # dat.drop(dat.head(1).index, inplace=True)
                    print("len after dropping head", len(dat))
                    # print(dat)
                    axes = dat.plot.line(
                            ax=axes, grid=True, 
                            lw=1,
                            # label=ns3_attributes[attribute][0].format(type=name),
                            # index=pd.date_range('1/1/2000', periods=1000)
                            )
                    # dat.plot.line(ax=ax, grid=True, lw=3)
                    # TODO retrieve legend from attributes + type
                    legends.append( ns3_attributes[attribute][0].format(idx=idx, type=name))

        plt.legend(legends)
        # log.info("Saving figure to %s" % output)
        fig.savefig(output)
        return fig



