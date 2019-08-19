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

# temporary solution to disable matplotlib logging
mpl_logger = logging.getLogger('matplotlib')
mpl_logger.setLevel(logging.WARNING)


def attributes(fields):
    return {name: field.label for name, field in fields.items() if field.label}


class PlotSubflowAttribute(plot.Matplotlib):
    """
    Plot one or several mptcp attributes (dsn, dss, etc...) on a same plot.
    This should be the most straightforward plot.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, x_label="Time (s)", **kwargs)

        # TODO filter the ones who have plot name
        self._attributes = attributes(self.tshark_config.fields)


    def default_parser(self, *args, **kwargs):

        pcaps = {
            "pcap": PreprocessingActions.Preload | PreprocessingActions.FilterMpTcpStream
        }

        parser = gen_pcap_parser(pcaps, direction=True)
        parser.description = "Plot MPTCP subflow attributes over time"

        parser.add_argument('field', choices=self._attributes.keys(),
            help="Choose an mptcp attribute to plot")
        res = super().default_parser(
            *args, parents=[parser],
            **kwargs)
        return res

    def plot(self, pcap, pcapstream, field, **kwargs):
        """
        getcallargs
        """
        fig = plt.figure()

        log.info("Plotting field %s", field)
        log.info("len(df)= %d", len(pcap))

        axes = fig.gca()
        destinations = kwargs.get("pcap_destinations")

        con = pcap.mptcp.connection(pcapstream)
        df = con.fill_dest(pcap)

        field_desc = self._attributes[field]
        title_fmt = "{field}"
        if len(destinations) == 1:
            title_fmt = title_fmt + " towards " + (destinations[0].to_string())
        title_fmt = title_fmt + " for MPTCP stream {mptcpstream}"

        # self.title_fmt = f"Subflow {field}"
        # fig.suptitle("Subflow %s" % field,
        #     verticalalignment="top",
        #     # x=0.1, y=.95,
        #              )
        fields = ["tcpstream", "mptcpdest"]


        for idx, subdf in df.groupby(fields, sort=False):
            tcpstream, mptcpdest = idx
            mptcpdest = mp.ConnectionRoles(mptcpdest)
            if mptcpdest not in destinations:
                log.debug("Ignoring MPTCP destination %s", mptcpdest)
                continue

            log.debug("Plotting mptcp destination %s", mptcpdest)
            log.info("len(df)= %d" % len(df))

            label_fmt = f"Subflow {tcpstream}"
            # for idx, (streamid, ds) in enumerate(tcpstreams):
            subdf[field].plot.line(
                x="abstime",
                ax=axes,
                # use_index=False,
                label=label_fmt,
                legend=True,
                grid=True,
            )

        self.y_label = field_desc

        self.title_fmt = title_fmt.format(field=field_desc, mptcpstream=pcapstream)
        return fig


class PlotTcpAttribute(plot.Matplotlib):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self._attributes = attributes(self.tshark_config.fields)

    def default_parser(self, *args, **kwargs):
        # TODO add filter_dest ?
        pcaps = {
            "pcap": plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterTcpStream
        }
        # can we filter dest ?
        parser = gen_pcap_parser(pcaps, True)

        parser.description = "Plot tcp attributes over time"
        parser.add_argument(
            '--syndrop', action="store_true",
            help="Drops first 3 packets of the dataframe assuming they are syn"
        )
        parser.add_argument(
            'fields', nargs='+',
            # action="append",
            choices=self._attributes.keys(),
            help="Choose a tcp attribute to plot"
        )
        res = super().default_parser(
            *args, parents=[parser],
            **kwargs)
        return res

    def plot(self, pcap, pcapstream, fields, pcap_destinations, **kwargs):
        """
        getcallargs
        """
        log.debug("Plotting field(s) %s", fields)

        fig = plt.figure()
        axes = fig.gca()

        tcpdf = pcap

        # should be done when filtering the stream
        tcpdf.tcp.fill_dest(pcapstream)

        labels = []  # type: List[str]

        for dest, ddf in tcpdf.groupby(_sender("tcpdest")):
            if dest not in pcap_destinations:
                log.debug("Ignoring destination %s", dest)

            log.debug("Plotting destination %s", dest)

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
                # the astype is a workaround pandas failure
                final.astype("int64").plot(
                    x=_sender("abstime"),
                    ax=axes,
                    use_index=False,
                    legend=False,
                    grid=True,
                )
                label_fmt = "{field} towards {dest}"
                labels.append(label_fmt.format(field=self._attributes[field], dest=str(dest)))

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

        self.title_fmt = " %s " % y_label

        return fig
