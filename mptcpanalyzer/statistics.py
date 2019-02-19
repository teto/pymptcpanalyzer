from typing import List, Any, Tuple, Dict, Callable, Union
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
from mptcpanalyzer import ConnectionRoles
from mptcpanalyzer.data import classify_reinjections
from mptcpanalyzer import _sender, _receiver, TcpStreamId, MpTcpStreamId, MpTcpException
import math
import logging
from dataclasses import dataclass

"""
Considerations:
- tcp.analysis.retransmission
- tcp.analysis.lost_segment
- tcp.analysis.fast_retransmission

https://osqa-ask.wireshark.org/questions/16771/tcpanalysisretransmission
"""

log = logging.getLogger(__name__)


# TcpConnectionStats ?
@dataclass
class TcpStats:
    tcpstreamid : TcpStreamId
    throughput_bytes: int
    tcp_goodput: int = None # ex tcp_goodput
    mptcp_goodput: int = None
    throughput_contribution: int = None # %
    goodput_contribution: int = None  # %

@dataclass
class MpTcpStats:
    mptcpstreamid: MpTcpStreamId
    # TODO append bytes
    mptcp_goodput_bytes: int
    subflow_stats: List[TcpStats]
    mptcp_goodput: int = None

    @property
    def mptcp_throughput_bytes(self):
        return sum(map(lambda x: x.throughput_bytes, self.subflow_stats))


# or throw exception instead ?
def mptcp_compute_throughput(
    rawdf, mptcpstreamid, destination: ConnectionRoles
    # mptcpstreamid2=None
) -> MpTcpStats:
    """
    Very raw computation: substract highest dsn from lowest by the elapsed time

    Returns:
        a tuple (True/false, dict)
    """

    df = rawdf[rawdf.mptcpstream == mptcpstreamid]
    if df.empty:
        raise MpTcpException("No packet with mptcp.stream == %d" % mptcpstreamid)

    con = MpTcpConnection.build_from_dataframe(df, mptcpstreamid)
    q = con.generate_direction_query(destination)
    df = unidirectional_df = df.query(q)

    dsn_min = df.dss_dsn.min()
    dsn_max = df.dss_dsn.max()
    total_transferred = dsn_max - dsn_min
    d = df.groupby(_sender('tcpstream'))
    subflow_stats: List[TcpStats] = []
    for tcpstream, group in d:
        # TODO drop retransmitted
        subflow_load = group.drop_duplicates(subset="dss_dsn").dss_length.sum()
        subflow_load = subflow_load if not math.isnan(subflow_load) else 0
        subflow_stats.append(
            TcpStats(tcpstreamid=tcpstream, throughput_bytes= int(subflow_load))
        )

    return MpTcpStats(
        mptcpstreamid=mptcpstreamid,
        # TODO append bytes
        mptcp_goodput_bytes=total_transferred,
        # mptcp_throughput_bytes=sum(map(lambda x: x.throughput_bytes, subflow_stats)),
        subflow_stats=subflow_stats,
    )


# TODO rename goodput
def mptcp_compute_throughput_extended(
    rawdf,  # need the rawdf to classify_reinjections
    stats: MpTcpStats,  # result of mptcp_compute_throughput
    destination: ConnectionRoles,
) -> MpTcpStats:
    """
    df expects an extended dataframe

    Should display goodput
    """
    df_both = classify_reinjections(rawdf)

    df = df_both[df_both.mptcpdest == destination]

    print(stats.subflow_stats)
    print(df.columns)

    for sf in stats.subflow_stats:
        log.debug("for tcpstream %d" % sf.tcpstreamid)
        # columns.get_loc(_first('abstime'))]
        df_sf = df[df.tcpstream == sf.tcpstreamid]
        # TODO eliminate retransmissions too
        # sum( map(lambda x: x['bytes'], subflow_stats)),

        # inexact, we should drop lost packets
        # tcplen ? depending on destination / _receiver/_sender
        tcp_throughput = df_sf["tcplen"].sum()
        # mptcp_goodput = df[df_sf.redundant == False, "throughput_bytes"].sum()

        # won
        seq_min = df_sf.tcpseq.min()
        seq_max = df_sf.tcpseq.max()

        tcp_goodput = seq_max - seq_min

        mptcp_goodput = df[df_sf.redundant == False, "throughput_bytes"].sum()
        sf_mptcp_throughput = tcp_throughput

        sf.tcp_goodput = tcp_goodput;
        sf.mptcp_goodput = mptcp_goodput  # cumulative sum of nonredundant dsn packets

        # can be > 1 in case of redundant packets
        sf.throughput_contribution = sf_mptcp_throughput/stats.mptcp_throughput_bytes
        sf.goodput_contribution = mptcp_goodput/stats.mptcp_goodput

    # for every subflow 
    # for tcpstream, group in df.groupby( _sender("tcpstream")):
    #     print("for tcpstream %d" % tcpstream)
    #     group[ df.redundant == False, "redundant"].sum()

    return  stats
