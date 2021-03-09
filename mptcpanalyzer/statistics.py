"""
Considerations:
- tcp.analysis.retransmission
- tcp.analysis.lost_segment
- tcp.analysis.fast_retransmission

https://osqa-ask.wireshark.org/questions/16771/tcpanalysisretransmission
"""

from typing import List, Any, Tuple, Dict, Callable, Union
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
from mptcpanalyzer import ConnectionRoles
import mptcpanalyzer as mp
from mptcpanalyzer.data import classify_reinjections
from mptcpanalyzer import (_sender, _receiver, TcpStreamId, MpTcpStreamId, MpTcpException,
    _first, _second)
from mptcpanalyzer.debug import debug_dataframe
import math
import datetime
import logging
from dataclasses import dataclass, field
from bitmath import Byte

log = logging.getLogger(__name__)


@dataclass
class TcpUnidirectionalStats:
    tcpstreamid: TcpStreamId
    ''' sum of tcplen / should be the same for tcp/mptcp
    Include redundant packets contrary to '''
    throughput_bytes: Byte

    tcp_duration: datetime.timedelta

    ''' For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    tcp_byte_range: int = None

    ''' application data = goodput = useful bytes '''
    mptcp_application_bytes: Byte = None

    throughput_contribution: float = None
    goodput_contribution: float = None  # %

    ''' For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    tcp_goodput: Byte = None  # ex tcp_goodput

    @property
    def mptcp_goodput_bytes(self) -> Byte:
        return self.mptcp_application_bytes

    @property
    def rate(self) -> Byte:
        return self.mptcp_application_bytes

@dataclass
class MpTcpUnidirectionalStats:
    '''
    Holds MPTCP statistics for one direction
    '''
    mptcpstreamid: MpTcpStreamId

    ''' application data = goodput = useful bytes '''
    ''' max(dsn)- min(dsn) - 1'''
    mptcp_application_bytes: Byte

    '''Total duration of the mptcp connection'''
    mptcp_duration: datetime.timedelta
    subflow_stats: List[TcpUnidirectionalStats]

    @property
    def mptcp_goodput_bytes(self) -> Byte:
        return self.mptcp_application_bytes

    @property
    def mptcp_throughput_bytes(self) -> Byte:
        ''' sum of total bytes transferred '''
        return Byte(sum(map(lambda x: x.throughput_bytes, self.subflow_stats)))

    @property
    def rate(self) -> Byte:
        return self.mptcp_application_bytes

def tcp_get_stats(
    rawdf,
    tcpstreamid: TcpStreamId,
    destination: ConnectionRoles,
    mptcp=False
) -> TcpUnidirectionalStats:
    '''
    Expects df to have tcpdest set
    '''
    log.debug("Getting TCP stats for stream %d", tcpstreamid)
    assert destination in ConnectionRoles, "destination is %r" % type(destination)

    df = rawdf[rawdf.tcpstream == tcpstreamid]
    if df.empty:
        raise MpTcpException("No packet with tcp.stream == %d" % tcpstreamid)

    df2 = df

    log.debug("df2 size = %d" % len(df2))
    log.debug("Looking at role %s" % destination)
    # assume it's already filtered ?
    sdf = df2[df2.tcpdest == destination]
    bytes_transferred = Byte(sdf["tcplen"].sum())
    assert bytes_transferred >= 0

    # -1 to account for SYN
    tcp_byte_range, seq_max, seq_min = transmitted_seq_range(sdf, "tcpseq")

    # print(sdf["abstime"].head())
    # print(dir(sdf["abstime"].dt))
    # print(sdf["abstime"].dt.end_time)
    times = sdf["abstime"]
    tcp_duration = times.iloc[-1] - times.iloc[0]
    # duration = sdf["abstime"].dt.end_time - sdf["abstime"].dt.start_time

    assert tcp_byte_range is not None

    return TcpUnidirectionalStats(
        tcpstreamid,
        tcp_duration=tcp_duration,
        throughput_bytes=bytes_transferred,
        # FIX convert to int because Byte does not support np.int64
        tcp_byte_range=Byte(tcp_byte_range)
    )


def transmitted_seq_range(df, seq_name):
    '''
    test
    '''
    log.debug("Computing byte range for sequence field %s", seq_name)

    sorted_seq = df.dropna(subset=[seq_name]).sort_values(by=seq_name)
    log.log(mp.TRACE, "sorted_seq %s", sorted_seq)

    seq_min = sorted_seq.loc[sorted_seq.first_valid_index(), seq_name]
    last_valid_index = sorted_seq.last_valid_index()
    seq_max = sorted_seq.loc[last_valid_index, seq_name] \
        + sorted_seq.loc[last_valid_index, "tcplen"]

    # -1 because of SYN
    # seq_range = seq_max - seq_min - 1
    seq_range = seq_max - seq_min - 1

    msg = "seq_range ({}) = {} (seq_max) - {} (seq_min) - 1"
    log.log(mp.TRACE, msg.format(seq_range, seq_max, seq_min))

    return seq_range, seq_max, seq_min


def mptcp_compute_throughput(
    rawdf,
    mptcpstreamid: MpTcpStreamId,
    destination: ConnectionRoles,
    merged_df: bool
) -> MpTcpUnidirectionalStats:
    """
    Very raw computation: substract highest dsn from lowest by the elapsed time
    Args:
        merged_df: True if merged_df

    Returns:
        a tuple (True/false, dict)
    """
    assert isinstance(destination, ConnectionRoles), "destination is %r" % destination

    con = rawdf.mptcp.connection(mptcpstreamid)
    q = con.generate_direction_query(destination)
    df = unidirectional_df = rawdf.query(q, engine="python")

    # -1 because of syn
    dsn_range, dsn_max, dsn_min = transmitted_seq_range(df, "dsn")

    msg = "dsn_range ({}) = {} (dsn_max) - {} (dsn_min) - 1"
    log.debug(msg.format(dsn_range, dsn_max, dsn_min))

    _col = _sender if merged_df else lambda x: x

    # print("test _sender %s" % _col("toto"))
    # Could groupby destination as well
    groups = df.groupby(_col('tcpstream'))

    subflow_stats: List[TcpUnidirectionalStats] = []
    for tcpstream, subdf in groups:
        # subdf.iloc[0, subdf.columns.get_loc(_second('abstime'))]
        # debug_dataframe(subdf, "subdf for stream %d" % tcpstream)
        dest = subdf.iloc[0, subdf.columns.get_loc(_col('tcpdest'))]
        sf_stats = tcp_get_stats(
            subdf, tcpstream,
            # work around pandas issue (since for now it's a float
            ConnectionRoles(dest),
            True
        )

        fields = ["tcpdest", "mptcpdest", "dss_dsn", "dss_length"]
        # debug_dataframe(subdf, "Debugging", usecols=[fields])

        # DSNs can be discontinuous, so we have to look at each packet
        # we drop duplicates
        transmitted_dsn_df = subdf.drop_duplicates(subset="dsn")

        sf_stats.mptcp_application_bytes = transmitted_dsn_df["tcplen"].sum()

        # + 1 to deal with syn oddity
        assert sf_stats.mptcp_application_bytes <= sf_stats.tcp_byte_range + 1, sf_stats

        log.log(mp.TRACE, "Adding subflow stats %r", sf_stats)
        subflow_stats.append(sf_stats)

    times = df["abstime"]
    duration = times.iloc[-1] - times.iloc[0]

    total_tput = sum(map(lambda x: x.throughput_bytes, subflow_stats))

    for sf in subflow_stats:
        # can be > 1 in case of redundant packets
        if total_tput > 0:
            sf.throughput_contribution = sf.throughput_bytes.bytes / total_tput
        else:
            sf.throughput_contribution = 0
            log.warning("Total Throughput <= 0. Something fishy possibly ?")


    """
    If it's a merged df, then we can classify reinjections and give more results
    on the goodput
    """
    if merged_df:
        df = classify_reinjections(unidirectional_df)

        debug_dataframe(df, "after reinjections have been analyzed")

        # mptcp_application_bytes = df.loc[df.redundant == False, "tcplen"].sum()
        for sf in subflow_stats:
            log.debug("for tcpstream %d" % sf.tcpstreamid)
            # columns.get_loc(_first('abstime'))]
            df_sf = df[df.tcpstream == sf.tcpstreamid]

            non_redundant_pkts = df_sf.loc[df_sf.redundant == False, "tcplen"]
            # print("non_redundant_pkts")
            # print(non_redundant_pkts)
            sf.mptcp_application_bytes = non_redundant_pkts.sum()
            # print("sf.mptcp_application_bytes" , sf.mptcp_application_bytes)

            sf.goodput_contribution = sf.mptcp_application_bytes / dsn_range


    return MpTcpUnidirectionalStats(
        mptcpstreamid=mptcpstreamid,
        mptcp_application_bytes=Byte(dsn_range),
        mptcp_duration=duration,
        subflow_stats=subflow_stats,
    )
