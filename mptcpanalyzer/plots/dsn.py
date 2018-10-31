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

        # print("mptcp_attr parser")
        parser = gen_pcap_parser(pcaps, )
        parser.description="Plot MPTCP subflow attributes over time"

        parser.add_argument('field', choices=self._attributes.keys(),
            help="Choose an mptcp attribute to plot")
        res = super().default_parser(
            *args, parents=[parser],
            # direction=True,
            # skip_subflows=True,
            **kwargs)
        # print("end of mptcp_attr parser")
        return res
        # return parser

    def plot(self, df, pcapstream, field, **kwargs):
        """
        getcallargs
        """
        fig = plt.figure()
        # tcpstreams = dat.groupby('tcpstream')

        # log.info("%d streams in the MPTCP flow" % len(tcpstreams))
        log.info("Plotting field %s" % field)
        log.info("len(df)= %d" % len(df))

        axes = fig.gca()

        fields = ["tcpstream", "mptcpdest"]

        fig.suptitle("Plot of subflow %s" % field,
            verticalalignment="top",
            # x=0.1, y=.95,
            )

        # il n'a pas encore eu les destinations !!
        print("DATASET HEAD")
        print(df.head())
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
        parser = gen_pcap_parser(pcaps, )

        # parent = argparse.ArgumentParser(
        parser.description="Plot tcp attributes over time"
        # )
        parser.add_argument('--syndrop', action="store_true",
            help="Will drop first 3 packets of the dataframe assuming they are syn")
        
        parser.add_argument('fields', nargs='+', 
            # action="append",
            choices=self._attributes.keys(),
            help="Choose an mptcp attribute to plot")
        # return parser
        return super().default_parser(
            *args, parents=[parser],
            # direction=True,
            # skip_subflows=True,
            **kwargs)



    def plot(self, df, tcpstream, fields, destinations, **kwargs):
        """
        getcallargs
        """
        fig = plt.figure()
        # tcpstreams = dat.groupby('tcpstream')

        # print("%d streams in the MPTCP flow" % len(tcpstream))
        log.debug("Plotting field(s) %s" % fields)

        axes = fig.gca()

        # for idx, (streamid, ds) in enumerate(tcpstreams):
        tcpdf = df
        # [df.tcpstream == tcpstream]

        # if dropsyn
        # tcpdf[field].iloc[3:]

        labels = [] # type: List[str]

        # TODO le .iloc permet d'eliminer les syn/ack
        # print("DTYPES")
        # print(tcpdf.dtypes)
        for dest, ddf in tcpdf.groupby(_sender("tcpdest")):
            # print("dest %r in %r" %( dest , destinations))
            # TODO remove ?
            if dest in destinations:

                for field in fields:
                    # print("dest", dest, " in " , destinations)

                    ddf[field].plot.line(
                        x=_sender("abstime"),
                        ax=axes,
                        # use_index=False,
                        legend=False,
                        grid=True,
                    )
                    labels.append("%s towards %s" % (self._attributes[field], dest))

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
