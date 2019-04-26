import mptcpanalyzer as mp
import mptcpanalyzer.plot as plot
import pandas as pd
import logging
import argparse
import matplotlib.pyplot as plt
from typing import List, Any, Tuple, Dict, Callable, Set
from mptcpanalyzer import _receiver, _sender, PreprocessingActions
from mptcpanalyzer.parser import gen_pcap_parser

log = logging.getLogger(__name__)

def attributes(fields):
    return { name: field.label for name, field in fields.items() if field.label }


class PlotSubflowAttribute(plot.Matplotlib):
    """
    Plot one or several mptcp attributes (dsn, dss, etc...) on a same plot.
    This should be the most straightforward plot.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # TODO filter the ones who have plot name
        self._attributes = attributes(self.tshark_config.fields)


    def default_parser(self, *args, **kwargs):

        pcaps = {
            "pcap": PreprocessingActions.Preload | PreprocessingActions.FilterMpTcpStream
        }

        parser = gen_pcap_parser(pcaps, )
        parser.description="Plot MPTCP subflow attributes over time"

        parser.add_argument('field', choices=self._attributes.keys(),
            help="Choose an mptcp attribute to plot")
        res = super().default_parser(
            *args, parents=[parser],
            **kwargs)
        # print("end of mptcp_attr parser")
        return res
        # return parser

    def plot(self, df, pcapstream, field, **kwargs):
        """
        getcallargs
        """
        fig = plt.figure()

        log.info("Plotting field %s" % field)
        log.info("len(df)= %d" % len(df))

        axes = fig.gca()

        fields = ["tcpstream", "mptcpdest"]

        fig.suptitle("Subflow %s" % field,
            verticalalignment="top",
            # x=0.1, y=.95,
        )

        # no destinations yet !!
        # debug_dataframe(df, "DATASET HEAD")
        for idx, subdf in df.groupby(_sender(fields), sort=False):
            log.info("len(df)= %d" % len(df))

            # TODO check destination

            # for idx, (streamid, ds) in enumerate(tcpstreams):
            subdf[field].plot.line(
                x="abstime",
                ax=axes,
                # use_index=False,
                legend=False,
                grid=True,
            )

        axes.set_xlabel("Time (s)")
        axes.set_ylabel(self._attributes[field])

        handles, labels = axes.get_legend_handles_labels()

        # Generate "subflow X" labels
        # location: 3 => bottom left, 4 => bottom right
        axes.legend(
            handles,
            ["%s for Subflow %d" % (field, x) for x, _ in enumerate(labels)],
            loc=4
        )
        return fig


class PlotTcpAttribute(plot.Matplotlib):

    def __init__(self, *args, **kwargs):

        super(plot.Matplotlib, self).__init__(*args, **kwargs)
        self._attributes = attributes(self.tshark_config.fields)

    def default_parser(self, *args, **kwargs):
        pcaps = {
            "pcap": plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterTcpStream
        }
        # can we filter dest ?
        parser = gen_pcap_parser(pcaps, True)

        parser.description="Plot tcp attributes over time"
        parser.add_argument('--syndrop', action="store_true",
            help="Drops first 3 packets of the dataframe assuming they are syn"
        )
        parser.add_argument('fields', nargs='+',
            # action="append",
            choices=self._attributes.keys(),
            help="Choose a tcp attribute to plot"
        )
        res = super().default_parser(
            *args, parents=[parser],
            # direction=True,
            # skip_subflows=True,
            **kwargs)
        return res

    def plot(self, pcap, pcapstream, fields, pcap_destinations, **kwargs):
        """
        getcallargs
        """
        log.debug("Plotting field(s) %s" % fields)

        fig = plt.figure()
        axes = fig.gca()

        tcpdf = pcap

        # if dropsyn
        # tcpdf[field].iloc[3:]

        # should be done when filtering the stream
        tcpdf.tcp.fill_dest(pcapstream)

        labels = [] # type: List[str]

        for dest, ddf in tcpdf.groupby(_sender("tcpdest")):
            if dest not in pcap_destinations:
                log.debug("Ignoring destination %s" % dest)

            log.debug("Plotting destination %s" % dest)

            for field in fields:
                # print("dest", dest, " in " , destinations)

                final = ddf[field].drop_duplicates()
                print("dataframe to plot")
                print(final)

                # log.debug("Plotting field %s" % field)
                # print("len len(ddf[field])=%d" % len(ddf[field]))
                if len(ddf[field]) <= 0:
                    log.info("No datapoint to plot")
                    continue

                # drop duplicate ?

                final.astype("int32").plot(
                    x=_sender("abstime"),
                    ax=axes,
                    use_index=False,
                    legend=False,
                    grid=True,
                )
                labels.append("%s towards %s" % (self._attributes[field], dest.name))

        axes.set_xlabel("Time (s)")
        if len(fields) == 1:
            y_label = self._attributes[fields[0]]
        else:
            y_label = "/".join(fields)
        axes.set_ylabel(y_label)

        handles, _labels = axes.get_legend_handles_labels()

        # TODO generate correct labels ?

        # print(tcpdf[field].iloc[3:])
        # Generate "subflow X" labels
        # location: 3 => bottom left, 4 => bottom right
        axes.legend(
            handles,
            labels
        #     ["%s for Subflow %d" % (field, x) for x, _ in enumerate(labels)],
        #     loc=4
        )

        fig.suptitle(" %s " % y_label)

        return fig
