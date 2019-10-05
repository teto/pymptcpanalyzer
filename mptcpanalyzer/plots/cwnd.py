import mptcpanalyzer as mp
import mptcpanalyzer.plot as plot
import pandas as pd
import logging
import argparse
import matplotlib.pyplot as plt
from typing import List, Any, Tuple, Dict, Callable, Set
from mptcpanalyzer import _receiver, _sender, PreprocessingActions
from mptcpanalyzer.parser import gen_pcap_parser
from mptcpanalyzer.debug import debug_dataframe
import glob
import json

log = logging.getLogger(__name__)

# temporary solution to disable matplotlib logging
mpl_logger = logging.getLogger('matplotlib')
mpl_logger.setLevel(logging.WARNING)

class PlotCwnds(plot.Matplotlib):
    '''
    Plot congestion windows as reported by netlink's SOCK_DIAG
    and saved by this path_manager http://hackage.haskell.org/package/mptcp-pm-0.0.2

    Next generation of ss may also support this in the future but not yet
    '''

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

    def default_parser(self, *args, **kwargs):

        parser = super().default_parser(
            *args,
            # parents=[parser],
            **kwargs)
        parser.description = "Plot tcp attributes over time"
        # parser.add_argument(
        #     'folder', action="store",
        #     help="Folder where to find the json files."
        # )
        # parser.add_argument(
        #     'token', action="store",
        #     help="Folder where to find the json files."
        # )
        parser.add_argument(
            'globbing_pattern', action="store",
            help="Folder where to find the json files."
        )
        # parser.add_argument(
        #     'fields', nargs='+',
        #     # action="append",
        #     choices=self._attributes.keys(),
        #     help="Choose a tcp attribute to plot"
        # )
        return parser

    # def build_dataframe(self, folder, token):
    #     '''
    #     '''
    #     glob.glob(os.path.join(folder,

    def plot(self, globbing_pattern, **kwargs):
        """
        getcallargs
        """
        log.debug("Plotting cwnd(s) following globbing pattern", globbing_pattern)

        # self.build_datafram
        df = pd.DataFrame()
        pattern = globbing_pattern
        files = glob.glob(globbing_pattern)
        for f in files:
            print("Loading %s" % f)
            with open(f, "r") as fp:
                r = json.load(fp,)
                # print(r)
                print(r["subflows"])
                for sf in r["subflows"]:
                    df = df.append(sf, ignore_index=True)

        print(df.head())
        fig = plt.figure()
        axes = fig.gca()
        # TODO we should save ports as well
        fields = ["dstIp", "srcIp", "srcPort", "dstPort"]
        for grp, sdf in df.groupby(fields):

            log.debug("Plotting grp %s", grp)
            sdf.plot(
                # TODO should be the globbed pattern
                # x="",
                y="snd_cwnd",
                ax=axes,
            )



        # TODO fix dest
        self.title_fmt = " Congestion windows"

        return fig
