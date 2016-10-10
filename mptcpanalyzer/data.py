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

log = logging.getLogger(__name__)



# def build_connections_from_dataset(df: pd.DataFrame, mptcpstreams: List[int]) -> List[MpTcpConnection]:
#     """
#     """
#     connections
#     for mptcpstream, df in df1:
#         if mptcpstream not in idx:
#             continue


def map_tcp_packet(df, packet) -> List[Tuple[Any, int]]: #  Tuple(row, score)
    # instead should be index ?
    """
    Packets may disappear, get retransmitted


    Args:
        packet:
    """

    def cmp_packets(p1, p2):
        """
        returns a score
        """
        score = 0

        # crude approach, packet with most common fields is declared the best
        for field in df.columns:
            if getattr(p1, field) == getattr(p2, field):
                score += 10
        # if p1.tcpflags != p2.tcpflags:
        #     score -= 10

        # if p1.dsn != p2.dsn:
        #     score -= abs(p2.dsn - p1.dsn)

        # if p1.dack != p2.dack:
        #     score -= abs(p2.dack - p1.dack)

        # when several packets have same dsn/ack number, we add the difference between 
        # absolute times so that the first gets a better score to referee between those
        score -= abs(p2.abstime - p1.abstime)
        return score

    scores = []
    for row in df.itertuples():
        scores.append((row.index, cmp_packets(packet, row)))

    scores.sort()
    return scores


def map_tcp_packets(rawdf1, rawdf2, con1 : TcpConnection, con2 : TcpConnection) -> pd.DataFrame:
    """
    Presuppose that stream ids are laready mapped 
    algo:
        Computes a score on a per packet basis

    Returns:
        a dataframe with 
    """
    df1 = rawdf1[rawdf1["tcpstream"] == con1.tcpstreamid]
    df2 = rawdf2[rawdf1["tcpstream"] == con2.tcpstreamid]
    # DataFrame.add(other, axis='columns', level=None, fill_value=None)
    # adds a new column that contains only nan
    df1["mapped_index"] = np.nan

    # deep copy of the dataframe
    df_final = df1.copy()

    # Problem is to identify lost packets and retransmitted ones 
    # so that they map to the same or none ?
    #itertuples returns namedtuples
    for row in df1.itertuples():
        scores = map_tcp_packet(df2, row)
        # print(row)
        limit = 2
        print("first %d packets scores=\n%s" % (limit, scores[:limit]))
        # for row2 in df2.itertuples():

        # takes best score index
        df1.iloc[row.index, "mapped_index"] = scores[0][0]
    return df_final
    


# def compare_filtered_df(df1, mptcpstream1, df2, mptcpstream2) -> int :
def compare_filtered_df(df1, main, df2, other) -> float :
    """
    ALREADY FILTERED dataframes

    Returns:
        a score
        - '-inf' means it's not possible those 2 matched
        - '+inf' means 
    """

    score = 0
    # mptcpstream = df1[df1.mptcpstream]
    # print("df1=%r"% df1)
    # print("stream=", df1.indices) #, 'mptcpstream']
    # # df1.as_index
    # print("rows", df1.nth(0).index )
    # print("keys", df1.keys )
    # print("keys", df1.group_keys)
    # print(dir(df1))
    # main = MpTcpConnection.build_from_dataframe(df1, mptcpstream1)
    # other = MpTcpConnection.build_from_dataframe(df2, mptcpstream2)

    # tcpstreams1 = ds1.groupby('tcpstream')
    # tcpstreams2 = ds2.groupby('tcpstream')
    # log.debug ("ds1 has %d subflow(s)." % (len(tcpstreams1)))
    # log.debug ("ds2 has %d subflow(s)." % (len(tcpstreams2)))
    if len (main.subflows) != len(other.subflows):
        log.debug("FISHY: Datasets contain a different number of subflows (d vs d)" % ())
        score -= 5

    common_sf = []

    if main.server_key == other.server_key and main.client_key == other.client_key:
        log.debug("matching keys => same")
        return float('inf')


    # TODO check there is at least the master
    # with nat, ips don't mean a thing ?
    for sf in main.subflows:
        # TODO compute a score
        if sf in other.subflows or sf.reversed in other.subflows:
            log.debug("Subflow %s in common" % sf)
            score += 10
            common_sf.append(sf)
        else:
            log.debug("subflows don't match")
        # elif sf.master:
        #     return float('-inf')

    # TODO compare start times supposing cloak are insync ?
    return score


# TODO rename
def mptcp_match_connections(rawdf1 : pd.DataFrame, rawdf2: pd.DataFrame, idx: List[int]=None):


    mappings={}
    for mptcpstream1 in rawdf1["mptcpstream"].unique():
        if idx and mptcpstream1 not in idx:
            continue

        main = MpTcpConnection.build_from_dataframe(rawdf1, mptcpstream1)
        results = mptcp_match_connection(rawdf1, rawdf2, main)
        mappings.update({main: results})
    return mappings


# def mptcp_match_connection(rawdf1 : pd.DataFrame, rawdf2: pd.DataFrame, idx: List[int]=None):
def mptcp_match_connection(rawdf1 : pd.DataFrame, rawdf2: pd.DataFrame, main : MpTcpConnection):
    """
    .. warn: Do not trust the results yet WIP !

    This function tries to map a mptcp.stream from a dataframe (aka pcap) to mptcp.stream
    in another dataframe.

    It goes over 

    Todo:
        - Every stream should be mapped to only one other (add a check for that ?)


    Args:
        ds1, ds2
        idx : List of mptcpstream chosen from rawds1, for which we want the equivalent id in rawdf2

    Returns:
        a dict {Connection1: [(Connection2, score)])

    """
    log.warn("mapping between datasets is not considered trustable yet")
    results = [] # type: List[Tuple[Any, float]]
    # if idx
    #    filtereddf1. 
    # df1 = rawdf1.groupby("mptcpstream")
    # ds2 = rawdf2.groupby("mptcpstream")


    mappings={} # type: Dict[Tuple[Any, float]]
    # scores = 
    # df['id'],unique()

    # main = MpTcpConnection.build_from_dataframe(df, mptcpstream)
    score = -1 # type: float
    results = []

    for mptcpstream2 in rawdf2["mptcpstream"].unique():
        other = MpTcpConnection.build_from_dataframe(rawdf2, mptcpstream2)
        score = compare_filtered_df( rawdf1, main, rawdf2, other )
        if score > float('-inf'):
            results.append((other, score))
        
    # sort based on the score
    results.sort(key=lambda x: x[1])
    # filter()

    return results
    # 
    # if len(results):

