import mptcpanalyzer.plot as plot
import pandas as pd
import logging
import argparse
import matplotlib.pyplot as plt


class PlotSubflowAttribute(plot.Matplotlib):
    """
    Plot one or several mptcp attributes (dsn, dss, etc...) on a same plot.
    This should be the most straightforward plot.
    """

    def __init__(self, *args, **kwargs):
        pcaps = [("pcap", plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterMpTcpStream), ]
        super().__init__(*args, input_pcaps=pcaps, **kwargs)

        self._attributes = self.tshark_config.get_fields('name', 'label')


    def default_parser(self, *args, **kwargs):

        parent = argparse.ArgumentParser(
            description="Plot tcp attributes over time"
        )
        parser = super().default_parser(
            *args, parent_parsers=[parent],
            filterstream=True,
            direction=True,
            skip_subflows=True,
            **kwargs)
        parser.add_argument('field', choices=self._attributes.keys(),
            help="Choose an mptcp attribute to plot")
        return parser

    def plot(self, dat, mptcpstream, field=None, **kwargs):
        """
        getcallargs
        """
        fig = plt.figure()
        tcpstreams = dat.groupby('tcpstream')

        print("%d streams in the MPTCP flow" % len(tcpstreams))
        print("Plotting field %s" % field)

        axes = fig.gca()

        for idx, (streamid, ds) in enumerate(tcpstreams):
            ds[field].plot.line(
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


class PlotTcpAttribute(PlotSubflowAttribute):

    def __init__(self, *args, **kwargs):

        pcaps = [("pcap", plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterTcpStream), ]
        super(plot.Matplotlib, self).__init__(*args, input_pcaps=pcaps, **kwargs)
        self._attributes = self.tshark_config.get_fields('name', 'label')

    # def default_parser(self, *args, **kwargs):

    #     parent = argparse.ArgumentParser(
    #         description="Plot tcp attributes over time"
    #     )
    #     parser = super(PlotSubflowAttribute,self).default_parser(
    #         *args, parent_parsers=[parent],
    #         filterstream=True,
    #         direction=True,
    #         skip_subflows=True,
    #         **kwargs)
    #     # parser.add_argument('field', choices=self.mptcp_attributes.keys(),
    #     #     help="Choose an mptcp attribute to plot")
    #     return parser

    def plot(self, df, tcpstream, field=None, **kwargs):
        """
        getcallargs
        """
        fig = plt.figure()
        # tcpstreams = dat.groupby('tcpstream')

        # print("%d streams in the MPTCP flow" % len(tcpstream))
        print("Plotting field %s" % field)

        axes = fig.gca()

        # for idx, (streamid, ds) in enumerate(tcpstreams):
        tcpdf = df[df.tcpstream == tcpstream]

        # TODO le .iloc permet d'eliminer les syn/ack
        tcpdf[field].iloc[3:].plot.line(
            ax=axes,
            # use_index=False,
            legend=False,
            grid=True,
        )

        axes.set_xlabel("Time (s)")
        axes.set_ylabel(self._attributes[field])

        handles, labels = axes.get_legend_handles_labels()

        print(tcpdf[field].iloc[3:])
        # Generate "subflow X" labels
        # location: 3 => bottom left, 4 => bottom right
        # axes.legend(
        #     handles,
        #     ["%s for Subflow %d" % (field, x) for x, _ in enumerate(labels)],
        #     loc=4
        # )

        return fig
