from typing import List, Any, Tuple, Dict, Callable, Union
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
from mptcpanalyzer import ConnectionRoles
import mptcpanalyzer as mp
from mptcpanalyzer.data import classify_reinjections, tcpdest_from_connections
from mptcpanalyzer import (_sender, _receiver, TcpStreamId, MpTcpStreamId, MpTcpException,
    _first, _second)
from mptcpanalyzer.pdutils import debug_dataframe
import math
import logging
from dataclasses import dataclass, field

"""
Considerations:
- tcp.analysis.retransmission
- tcp.analysis.lost_segment
- tcp.analysis.fast_retransmission

https://osqa-ask.wireshark.org/questions/16771/tcpanalysisretransmission
"""

log = logging.getLogger(__name__)


# These should be unidirection
@dataclass
class TcpUnidirectionalStats:
    tcpstreamid: TcpStreamId
    # bytes: int
    ''' sum of tcplen / should be the same for tcp/mptcp'''
    throughput_bytes: int

    ''' For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    # rename to byte range ?
    tcp_transferred_bytes: int = None

    ''' max(dsn)- min(dsn) - 1'''
    mptcp_transferred_bytes: int = None
    # TODO convert to property ?
    throughput_contribution: float = None
    # throughput_contribution: int = field(default=None, metadata={'unit': '%'})
    goodput_contribution: float = None  # %

    ''' For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    tcp_goodput: int = None # ex tcp_goodput

    # @property
    # def throughput_contribution(self):
    #     return self.througput_bytes

    @property
    def mptcp_goodput_bytes(self):
        return self.mptcp_transferred_bytes

@dataclass
class MpTcpUnidirectionalStats:
    mptcpstreamid: MpTcpStreamId
    mptcp_transferred_bytes: int
    subflow_stats: List[TcpUnidirectionalStats]
    # TODO rename to global ?
    # mptcp_goodput_bytes: int = None

    @property
    def mptcp_goodput_bytes(self):
        return self.mptcp_transferred_bytes

    @property
    def mptcp_throughput_bytes(self):
        ''' sum of total bytes transferred '''
        return sum(map(lambda x: x.throughput_bytes, self.subflow_stats))


def tcp_get_stats(
    rawdf,
    tcpstreamid: TcpStreamId,
    destination: ConnectionRoles,
    mptcp=False
    ):
    '''
    Expects df to have tcpdest set
    '''
    # -> Tuple[TcpUnidirectionalStats, TcpUnidirectionalStats]:
    log.debug("Getting TCP stats for stream %d" % tcpstreamid)
    assert destination in ConnectionRoles, "destination is %r" % type(destination)

    df = rawdf[rawdf.tcpstream == tcpstreamid]
    if df.empty:
        raise MpTcpException("No packet with tcp.stream == %d" % tcpstreamid)

    # TODO do it only when needed
    # con = TcpConnection.build_from_dataframe(df, tcpstreamid)
    # df2 = tcpdest_from_connections(df, con)
    df2 = df

    log.debug("df2 size = %d" % len(df2))
    # q = con.generate_direction_query(destination)
    # df = unidirectional_df = df.query(q, engine="python")
    # return (TcpUnidirectionalStats(),  TcpUnidirectionalStats() )
    # res = { }
    # debug_dataframe(df2, "before connection", )
    # for destination in ConnectionRoles:
    log.debug("Looking at role %s" % destination)
    # print(df2["tcpdest"])
    # TODO assume it's already filtered ?
    sdf = df2[df2.tcpdest == destination]
    bytes_transferred = sdf["tcplen"].sum()
    # sdf["tcplen"].sum()
    # print("bytes  bytes_transferred ")

    seq_min = sdf.tcpseq.min()

    # TODO + add the last packet size ?
    seq_max = sdf.tcpseq.max()

    # -1 to accoutn for SYN
    tcp_transferred_bytes = seq_max - seq_min - 1
    msg = "tcp_transferred_bytes ({}) = {} (seq_max) - {} (seq_min) - 1"
    log.debug(msg.format(tcp_transferred_bytes, seq_max, seq_min))


    # if mptcp:
    #     print("do some extra work")
        # res[destination] = TcpUnidirectionalStats(tcpstreamid, bytes_transferred, 0, 0)


    return TcpUnidirectionalStats(
        tcpstreamid,
        throughput_bytes=bytes_transferred,
        tcp_transferred_bytes=tcp_transferred_bytes,
    )


# TODO same return both directions
def mptcp_compute_throughput(
    rawdf, mptcpstreamid: MpTcpStreamId, destination: ConnectionRoles
) -> MpTcpUnidirectionalStats:
    """
    Very raw computation: substract highest dsn from lowest by the elapsed time

    Returns:
        a tuple (True/false, dict)
    """
    assert isinstance(destination, ConnectionRoles), "destination is %r" % destination

    df = rawdf[rawdf.mptcpstream == mptcpstreamid]
    if df.empty:
        raise MpTcpException("No packet with mptcp.stream == %d" % mptcpstreamid)

    con = MpTcpConnection.build_from_dataframe(df, mptcpstreamid)
    q = con.generate_direction_query(destination)
    # print("query q= %r" % q)
    df = unidirectional_df = df.query(q, engine="python")

    dsn_min = df.dss_dsn.min()
    dsn_max = df.dss_dsn.max()
    # -1 because of syn
    dsn_range = dsn_max - dsn_min - 1

    log.debug("dsn_range ({}) = {} (dsn_max) - {} (dsn_min) - 1".format(
        dsn_range, dsn_max, dsn_min))

    # Could groupby destination as well
    d = df.groupby(_sender('tcpstream'))
    subflow_stats: List[TcpUnidirectionalStats] = []
    for tcpstream, subdf in d:
        # subdf.iloc[0, subdf.columns.get_loc(_second('abstime'))]
        # debug_dataframe(subdf, "subdf for stream %d" % tcpstream)
        dest = subdf.iloc[0, subdf.columns.get_loc(_sender('tcpdest'))]
        sf_stats = tcp_get_stats(subdf, tcpstream,
            # work around pandas issue
            ConnectionRoles(dest),
        True)

        # TODO drop retransmitted
        # assumes that dss.
        sf_dsn_min = subdf.dss_dsn.min()
        sf_dsn_max = subdf.dss_dsn.max()

        # subflow_load = subdf.drop_duplicates(subset="dss_dsn").dss_length.sum()
        # subflow_load = subflow_load if not math.isnan(subflow_load) else 0

        sf_stats.mptcp_transferred_bytes_bytes = sf_dsn_max - sf_dsn_min - 1

        subflow_stats.append(
            sf_stats
        )

    return MpTcpUnidirectionalStats(
        mptcpstreamid=mptcpstreamid,
        mptcp_transferred_bytes=dsn_range,
        subflow_stats=subflow_stats,
    )


# TODO rename goodput
def mptcp_compute_throughput_extended(
    rawdf,  # need the rawdf to classify_reinjections
    stats: MpTcpUnidirectionalStats,  # result of mptcp_compute_throughput
    destination: ConnectionRoles,
) -> MpTcpUnidirectionalStats:
    """
    df expects an extended dataframe

    Should display goodput
    """
    assert isinstance(destination, ConnectionRoles)
    log.debug("Looking at destination %r" % destination)
    df_both = classify_reinjections(rawdf)

    df = df_both[df_both.mptcpdest == destination]

    # print(stats.subflow_stats)
    # print(df.columns)

    stats.mptcp_transferred_bytes = df.loc[df.redundant == False, "tcplen"].sum()

    print("MATT mptcp throughput ", stats.mptcp_throughput_bytes)
    for sf in stats.subflow_stats:
        log.debug("for tcpstream %d" % sf.tcpstreamid)
        # columns.get_loc(_first('abstime'))]
        df_sf = df[df.tcpstream == sf.tcpstreamid]
        # TODO eliminate retransmissions too

        # inexact, we should drop lost packets
        # tcplen ? depending on destination / _receiver/_sender
        # tcp_throughput = df_sf["tcplen"].sum()

        # won
        # seq_min = df_sf.tcpseq.min()
        # seq_max = df_sf.tcpseq.max()

        # tcp_transferred_bytes = seq_max - seq_min

        # tcplen == 
        # _first / _second
        # or .loc
        # print ("DF.head")
        # print (df.head())
        # print ("columns", df.columns)
        non_redundant_pkts = df_sf.loc[df_sf.redundant == False, "tcplen"]
        # print(non_redundant_pkts)
        mptcp_transferred_bytes = non_redundant_pkts.sum()
        # print("mptcp_transferred_bytes" , mptcp_transferred_bytes)
        sf_mptcp_throughput = sf.throughput_bytes

        # sf.tcp_transferred_bytes = tcp_transferred_bytes;
        sf.mptcp_transferred_bytes = mptcp_transferred_bytes  # cumulative sum of nonredundant dsn packets

        # can be > 1 in case of redundant packets
        sf.throughput_contribution = sf_mptcp_throughput/stats.mptcp_throughput_bytes
        sf.goodput_contribution = mptcp_transferred_bytes/stats.mptcp_transferred_bytes

    return  stats
