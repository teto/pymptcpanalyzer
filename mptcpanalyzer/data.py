#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import pandas as pd
import numpy as np
from mptcpanalyzer.tshark import TsharkExporter, Filetype
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
from typing import List, Any, Tuple
import math

log = logging.getLogger(__name__)


def ignore(f1, f2):
    return 0


def exact(f1, f2):
    print("comparing ", f1 , " and " , f2)
    return float('-inf') if f1 != f2 else 10


def diff(f1, f2):
    return f2 - f1

"""
invariant: True if not modified by the network
Of the form Field.shortname

Have a look at the graphic slide 28:
https://www-phare.lip6.fr/cloudnet12/Multipath-TCP-tutorial-cloudnet.pptx
"""
scoring_rules = {
    "packetid": ignore,
    "abstime": diff, # in-order packets are more common than out of order ones
    "default_time": ignore,
    "expected_token": exact,
    "sport": exact,
    "dport": exact,
    "rwnd": exact,
    "sendkey": exact,
    "rcvkey": exact,
    "rcvtoken": exact,
    "tcpflags": exact,
    "dss_dsn": exact,
    "dss_rawack": exact,
    "dss_ssn": exact,
    "tcpseq": exact,
    "tcplen": exact,
    # "dsnraw64": exact,
}

# def build_connections_from_dataset(df: pd.DataFrame, mptcpstreams: List[int]) -> List[MpTcpConnection]:
#     """
#     """
#     connections
#     for mptcpstream, df in df1:
#         if mptcpstream not in idx:
#             continue



def map_tcp_packet(df, packet) -> List[Tuple[Any, float]]: # Tuple(row, score)
    # instead should be index ?
    """
    Packets may disappear, get retransmitted

    Args:
        packet:

    Returns:
        a list of tuples (index, score)
    """

    def _cmp_packets(p1, p2) -> float:
        """
        returns a score
        """
        # log.debug("comparing packets %s and %s" % (p1, p2))
        score = 0
        # crude approach, packet with most common fields is declared the best
        # log.debug("comparison based on columns %s " % df.columns)
        for field in df.columns:
            try:
                log.debug("comparing %d to %d for field " % (packet.Index, row.Index, field ))
                f1 = getattr(p1, field)
                f2 = getattr(p2, field)
                score += scoring_rules[field](f1, f2)
                # log.debug("new score after column [%s] = %f" % (field, score))
                if math.isinf(score):
                    log.debug("Score set to infinity  for field %s" % field)
                    break
            except Exception as e:
                pass
                # log.debug("Exception %s" % str(e))

        # when several packets have same dsn/ack number, we add the difference between 
        # absolute times so that the first gets a better score to referee between those
        # score -= abs(p2.abstime - p1.abstime)
        return score

    scores = [] # type: List[Any]

    for row in df.itertuples():

        score = _cmp_packets(packet, row)

        # we don't append inf results for performance reasons
        if not math.isinf(score):
            log.debug("packet %d mapped to %d with a score of %d" % (packet.Index, row.Index, score))
            scores.append((row.Index, score))
        else:
            log.debug("Found no match for %d, skipping.." % (packet.Index))

    # sort by score
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores


def map_tcp_packets(    
    sender_df, receiver_df, 
        # con1: TcpConnection, con2: TcpConnection
) -> pd.DataFrame:
    """
    Stream ids must already mapped 
    
    Todo:
        check N = len(sender_df) - len(receiver_df) to know how many packets should be missing,
        then cut off lowest N.

    algo:
        Computes a score on a per packet basis
        Based 

    Returns:
        a copy of rawdf1 with as Index the packetid + a new column called 
        "mapped_index" matching the Index of rawdf2
    """
    # DataFrame.add(other, axis='columns', level=None, fill_value=None)
    # adds a new column that contains only nan
    log.debug("Mapping TCP packets between TODO")
    # df1 = sender_df.set_index('packetid', )
    # df2 = receiver_df.set_index('packetid',) # [rawdf2["tcpstream"] == con2.tcpstreamid]
    # df1 = sender_df
    # df2 = rawdf2
    # df2.set_index('packetid', inplace=True)

    # returns a new df with new columns
    df_final = sender_df.assign(rcv_pktid=np.nan, score=np.nan, ) # =np.nan)

    # # Problem is to identify lost packets and retransmitted ones 
    # # so that they map to the same or none ?
    limit = 5

    # df_res = pd.DataFrame(columns=['packetid', 'score', "mapped_rcvpktid"])
    for row in sender_df.itertuples():
        # print("len(df2)=", len(df2))
        scores = map_tcp_packet(receiver_df, row)
        print("first %d packets (pandas.index/score)s=\n%s" % (limit, scores[:limit]))
        # takes best score index
        # print("row=", df_final.loc[row.index, "packetid"])
        # df_final.loc[row.index , 'mapped_index'] = 2 # scores[0][0]
        # print(type(row.Index), type(row.index))
        if len(scores) >= 1:
            idx, score = scores[0]

            df_final.set_value(row.Index, 'rcv_pktid', idx)
            df_final.set_value(row.Index, 'score', score)

        # drop the chosen index so that it doesn't get used a second time
        # todo pb la c qu'on utilise les packet id comme des index :/
            print("Score %f assigned to index %s" % (score, idx))
            # print(df2)
            # df2.drop(df2.index[[idx]], inplace=True)
            df2.drop(idx, inplace=True)
        else:
            log.debug("No map found for this packet")

        # print("registered = %s" % ( df_final.loc[row.Index, 'mapped_index'])) # , ' at index: ', row.index ) 

    print("head=\n", df_final.head())
    return df_final




def mptcp_match_connections(rawdf1: pd.DataFrame, rawdf2: pd.DataFrame, idx: List[int]=None):


    mappings = {}
    for mptcpstream1 in rawdf1["mptcpstream"].unique():
        if idx and mptcpstream1 not in idx:
            continue

        main = MpTcpConnection.build_from_dataframe(rawdf1, mptcpstream1)
        results = mptcp_match_connection(rawdf2, main)
        mappings.update({main: results})
    return mappings


def map_tcp_stream(rawdf: pd.DataFrame, main: TcpConnection):
    """
    """

    results = []
    for tcpstream in rawdf["tcpstream"].unique():
        other = TcpConnection.build_from_dataframe(rawdf, tcpstream)
        score = main.score(other)
        if score > float('-inf'):
            results.append((other, score))

    # sort based on the score
    results.sort(key=lambda x: x[1], reverse=True)

    return results


def mptcp_match_connection(
    rawdf2: pd.DataFrame, main: MpTcpConnection
) -> List[Tuple[MpTcpConnection, float]]:
    """
    .. warn: Do not trust the results yet WIP !

    This function tries to map a mptcp.stream from a dataframe (aka pcap) to mptcp.stream
    in another dataframe.

    It goes over 

    Args:
        ds1, ds2

    """
    log.warning("mapping between datasets is not considered trustable yet")
    results = [] # type: List[Tuple[Any, float]]

    mappings = {} # type: Dict[int,Tuple[Any, float]]

    # main = MpTcpConnection.build_from_dataframe(df, mptcpstream)
    score = -1 # type: float
    results = []

    for mptcpstream2 in rawdf2["mptcpstream"].unique():
        other = MpTcpConnection.build_from_dataframe(rawdf2, mptcpstream2)
        score = main.score(other)
        if score > float('-inf'):
            results.append((other, score))

    # sort based on the score
    results.sort(key=lambda x: x[1], reverse=True)

    return results
