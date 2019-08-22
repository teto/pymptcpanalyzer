import mptcpanalyzer.plot as plot
import mptcpanalyzer as mp
import matplotlib.pyplot as plt
import matplotlib as mpl
from itertools import cycle
import logging
from mptcpanalyzer.parser import gen_pcap_parser
from mptcpanalyzer.debug import debug_dataframe

log = logging.getLogger(__name__)

class DssLengthHistogram(plot.Matplotlib):
    """
    Plots histogram

    .. warning:: WIP
    """

    def __init__(self, *args, **kwargs):
        super().__init__(
            args,
            title="DSS Length",
            **kwargs
        )

    def default_parser(self, *args, **kwargs):

        pcaps = {
            "pcap": plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterStream,
        }

        parser = gen_pcap_parser(pcaps, direction=True)
        # force to choose a destination
        parser.add_argument('--dack', action="store_true", default=False,
            help="Adds data acks to the graph")

        # can only be raw as there are no relative dss_dsn exported yet ?
        # parser.add_argument('--relative', action="store_true", default=False,
        #         help="Adds data acks to the graph")
        parser.description = "TEST description"
        parser.epilog = "test epilog"
        return parser

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
    Draw small arrows with dsn as origin, and a *dss_length* length etc...
    Also allow to optionally display dataack

    As the generated plot can end up being quite rich, it is a good idea to specify
    a |matplotlibrc| with high dimensions and high dpi.

    Todo:
        - if there is an ack add that to legend
        - ability to display relative #seq
    """

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            title="dsn",
            x_label="Time (s)",
            y_label="Data Sequence Number",
            **kwargs
        )

    def default_parser(self, *args, **kwargs):

        pcaps = {
            # TODO FilterDestination
            "pcap": plot.PreprocessingActions.Preload | plot.PreprocessingActions.FilterStream,
        }

        # TODO maybe allow only one direction
        # TODO allow to choose between relative and absolute
        parser = gen_pcap_parser(pcaps, direction=True)


        # force to choose a destination
        parser.add_argument('--dack', action="store_true", default=False,
            help="Adds data acks to the graph")

        # can only be raw as there are no relative dss_dsn exported yet ?
        # parser.add_argument('--relative', action="store_true", default=False,
        #         help="Adds data acks to the graph")
        parser.description = "TEST description"
        parser.epilog = "test epilog"
        return parser

    def plot(self, pcap, pcapstream, pcap_destinations, dack=False, relative=None, **args):
        """
        Might be

        """
        dack_str = "dss_rawack"
        dsn_str = "dss_dsn"
        # dsn_str = "dsn"


        debug_dataframe(pcap, "dss")

        rawdf = pcap.set_index("reltime")

        print("pcapstream", pcapstream)
        con = rawdf.mptcp.connection(pcapstream)
        df = con.fill_dest(rawdf)

        # only select entries with a dss_dsn
        # df_forward = self.preprocess(rawdf, destination=destination, extra_query="dss_dsn > 0", **args)

        # kinda buggy
        destination = pcap_destinations[0]
        print("destination:", destination)

        # tcpdest or mptcpdest
        df_forward = df[df.mptcpdest == destination]
        df_forward = df_forward[df_forward[dsn_str] > 0]
        debug_dataframe(df_forward, "Forward dest", usecols=["dsn", "mptcpdest", "dss_dsn", "dss_length"])

        # compute limits of the plot
        # ymin, ymax = float('inf'), 0
        # ymin, ymax = min(ymin, df_forward[dsn_str].min()), max(ymax, df_forward[dsn_str].max())
        ymin, ymax = df_forward[dsn_str].min(), df_forward[dsn_str].max()
        print("setting ymin/ymax", ymin, ymax)

        fig = plt.figure()
        axes = fig.gca()

        # plt.vlines([0, 1], 0, 3)

        def show_dss(idx, row, style):
            """
            dss_dsn
            """
            # returns a FancyArrow
            # print("dss_length", row["dss_length"],)
            print("Arrow settings: origin=%s/%d with length %d" % (idx, int(row[dsn_str]), row["dss_length"]))
            res = axes.arrow(
                idx,
                int(row[dsn_str]),  # x, y
                0,
                row["dss_length"],    # dx, dy
                # 20,
                # head_width=0.05,
                head_width=0.08,
                # head_length=0.00002
                head_length=0.1,
                # length_includes_head=True,
                **style
            )
            res.set_label("hello")
            return res

        handles, labels = axes.get_legend_handles_labels()


        # TODO cycle manually through
        cycler = mpl.rcParams['axes.prop_cycle']
        styles = cycle(cycler)
        legends = []
        legend_artists = []

        df_forward.set_index("abstime", inplace=True)

        ### Plot dss dsn (forward)
        ######################################################
        for tcpstream, df in df_forward.groupby('tcpstream'):
            style = next(styles)
            print("arrows for tcpstream %d" % tcpstream)

            # style = next(styles)

            artist_recorded = False
            # TODO itertuples should be faster
            for index, row in df_forward.iterrows():
                artist = show_dss(
                    index,
                    # row["packetid"],
                    row,
                    style
                )
                print("artists %r" % artist)
                if not artist_recorded:
                    legend_artists.append(artist)
                    artist_recorded = True

            if artist_recorded:
                legends.append("dss for Subflow %d" % tcpstream)


        ### if enabled, plot dack (backward)
        ######################################################
        # TODO fix
        if dack:
            df_backward = self.preprocess(rawdf, **args, destination=mp.reverse_destination(destination),
                    extra_query=dack_str + " >=0 ")

            for tcpstream, df in df_backward.groupby('tcpstream'):
                # marker = next(markers)
                if df.empty:
                    log.debug("No dack for tcpstream %d", tcpstream)
                else:
                    ax1 = df[dack_str].plot.line(ax=axes, legend=False)
                    lines, labels = ax1.get_legend_handles_labels()
                    legend_artists.append(lines[-1])
                    legends.append("dack for sf %d" % tcpstream)

        # location: 3 => bottom left, 4 => bottom right
        axes.legend(legend_artists, legends, loc=4)

        # xmin, xmax = 0, 5000
        # axes.set_xlim([xmin, xmax])
        # axes.set_ylim([ymin, ymax])
        axes.relim()
        axes.autoscale_view()
        # axes.autoscale(enable=True, axis="both")

        return fig
