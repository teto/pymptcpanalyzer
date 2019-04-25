import mptcpanalyzer.plot as plot
import mptcpanalyzer as mp
import matplotlib.pyplot as plt
import matplotlib as mpl
from itertools import cycle
import logging

log = logging.getLogger(__name__)

class DssLengthHistogram(plot.Matplotlib):
    """
    Plots histogram

    .. warning:: WIP
    """

    def __init__(self, *args, **kwargs):
        input_pcaps = {
            "pcap": plot.PreprocessingActions.Preload,
        }
        super().__init__(
                args,
                input_pcaps=input_pcaps,
                title="DSS Length",
                **kwargs
            )

    def plot(self, df, mptcpstream, **kwargs):

        fig = plt.figure()
        axes = fig.gca()
        df.set_index("reltime", inplace=True)
        field = "dss_length"
        pplot = df[field].plot.hist(
            ax=axes,
            legend=True,
            grid=True,
        )
        return fig


class DSSOverTime(plot.Matplotlib):
    """
    WIP
    Draw small arrows with dsn as origin, and a *dss_length* length etc...
    Also allow to optionally display dataack

    As the generated plot can end up being quite rich, it is a good idea to specify
    a |matplotlibrc| with high dimensions and high dpi.

    Todo:
        - if there is an ack add that to legend
        - ability to display relative #seq
    """

    def __init__(self, *args, **kwargs):
        expected_pcaps = {
            "pcap": plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterStream,
        }
        super().__init__(
            *args,
            input_pcaps=expected_pcaps,
            title="dsn",
            **kwargs
        )

    def default_parser(self, *args, **kwargs):
        parser = super().default_parser(*args,
                direction=True, **kwargs)
        parser.add_argument('--dack', action="store_true", default=False,
                help="Adds data acks to the graph")

        # can only be raw as there are no relative dss_dsn exported yet ?
        # parser.add_argument('--relative', action="store_true", default=False,
        #         help="Adds data acks to the graph")
        parser.description = "TEST description"
        parser.epilog = "test epilog"
        return parser

    def plot(self, rawdf, destination=None, dack=False, relative=None, **args):
        """
        Might be

        """
        dack_str = "dss_rawack"
        dsn_str = "dss_dsn"

        ymin, ymax = float('inf'), 0

        rawdf.set_index("reltime", inplace=True)

        df_forward = self.preprocess(rawdf, destination=destination, extra_query="dss_dsn > 0", **args)

        # compute limits of the plot
        ymin, ymax = min(ymin, df_forward[dsn_str].min()), max(ymax, df_forward[dsn_str].max())

        fig = plt.figure()
        axes = fig.gca()

        def show_dss(idx, row, style):
            """
            dss_dsn
            """
            # returns a FancyArrow
            res = axes.arrow(idx, int(row[dsn_str]) , 0, row["dss_length"],
                    head_width=0.05, head_length=0.1, **style)
            res.set_label("hello")
            return res

        handles, labels = axes.get_legend_handles_labels()


        # TODO cycle manually through
        cycler = mpl.rcParams['axes.prop_cycle']
        styles = cycle(cycler)
        legends = []
        legend_artists = []

        ### Plot dss dsn (forward)
        ######################################################
        for tcpstream, df in df_forward.groupby('tcpstream'):
            style = next(styles)
            print("arrows for tcpstream %d" % tcpstream)

            style = next(styles)

            artist_recorded = False
            # TODO itertuples should be faster
            for index, row in df_forward.iterrows():
                artist = show_dss(index, row, style)
                if not artist_recorded:
                    legend_artists.append(artist)
                    artist_recorded = True

            if artist_recorded:
                legends.append("dss for Subflow %d" % tcpstream)



        ### if enabled, plot dack (backward)
        ######################################################
        if dack:
            df_backward = self.preprocess(rawdf, **args, destination=mp.reverse_destination(destination),
                    extra_query=dack_str + " >=0 ")


            #TODO remove the cycler in favor of something 
            # cycler = mpl.cycler(marker=['s', 'o', 'x'], color=['r', 'g', 'b'])
            # markers = cycle(cycler)

            for tcpstream, df in df_backward.groupby('tcpstream'):
                # marker = next(markers)
                if df.empty:
                    log.debug("No dack for tcpstream %d" % tcpstream)
                else:
                    ax1 = df[dack_str].plot.line(ax=axes,
                            # style=marker,
                            legend=False
                    )
                    lines, labels = ax1.get_legend_handles_labels()
                    legend_artists.append(lines[-1])
                    legends.append("dack for sf %d" % tcpstream)

        # location: 3 => bottom left, 4 => bottom right
        axes.legend(legend_artists, legends, loc=4)

        axes.set_ylabel("Data Sequence Number (DSN)")
        axes.set_xlabel("Relative time (s)")
        axes.set_ylim([ymin,ymax])
        return fig

