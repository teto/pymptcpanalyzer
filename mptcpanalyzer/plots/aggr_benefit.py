#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import mptcpanalyzer.plot as plot
import mptcpanalyzer as mp
from mptcpanalyzer.connection import MpTcpConnection
import pandas as pd
import logging
import matplotlib.pyplot as plt
import os

log = logging.getLogger(__name__)


class PlotAggregationBenefit(plot.Matplotlib):
    """
    .. math::

        \begin{equation}
                Ben(s) = \begin{cases}
                        \frac{g - C_{max}}{\sum^n_{i=1} C_i - C_{max}} \text{if} g \ge C_{max}\\
                        \frac{g - C_{max}}{C_{max}} \text{if} g < C_{max}
                \end{cases}
        \end{equation}

    """
    def plot(df, mptcpstream, field, **kwargs):
        """
        We get min/max
        Need a direction !
         idxmin() and idxmax()
        """
        # need to look for min/max DSN on each subflow
        con = MpTcpConnection.build_from_dataframe(df, mptcpstream)

        # streams = df.groupby("tcpstream")
        for subflow in con.subflows:
            ds = df.query(subflow.generate_direction_query())
            min_dsn, max_dsn = ds["dsn"].min(), ds["dsn"].max()
            print("Transferred bytes on subflow %s =" % (subflow, max_dsn - min_dsn))
        # df.bar()
        # df.boxplot()

