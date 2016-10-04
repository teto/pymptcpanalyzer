#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import pandas as pd
from mptcpanalyzer.tshark import TsharkExporter, Filetype
from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection
from typing import List

log = logging.getLogger(__name__)



def build_connections_from_dataset(df: pd.DataFrame, mptcpstreams: List[int]) -> List[MpTcpConnection]:
    """
    """
    connections
    for mptcpstream, df in df1:
        if mptcpstream not in idx:
            continue


# def compare_filtered_df(df1, mptcpstream1, df2, mptcpstream2) -> int :
def compare_filtered_df(df1, main, df2, other) -> int :
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

def map_subflows_between_2_datasets(rawdf1 : pd.DataFrame, rawdf2: pd.DataFrame, idx: List[int]=None):
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
        a dict of tuples (Connection1, Connection2)

    """
    log.warn("mapping between datasets is not considered trustable yet")
    results = [] # :type List[tuples]
    # if idx
    #    filtereddf1. 
    # df1 = rawdf1.groupby("mptcpstream")
    # ds2 = rawdf2.groupby("mptcpstream")


    mappings={}
    # scores = 
    # df['id'],unique()
    for mptcpstream1 in rawdf1["mptcpstream"].unique():
        if idx and mptcpstream1 not in idx:
            continue


        main = MpTcpConnection.build_from_dataframe(rawdf1, mptcpstream1)

        # main = MpTcpConnection.build_from_dataframe(df, mptcpstream)
        score = -1
        results = []

        for mptcpstream2 in rawdf2["mptcpstream"].unique():
            # other = MpTcpConnection.build_from_dataframe(df2, mptcpstream)
            # other = 
            other = MpTcpConnection.build_from_dataframe(rawdf2, mptcpstream2)
            score = compare_filtered_df( rawdf1, main, rawdf2, other )
            if score > float('-inf'):
                results.append((other, score))
            
        # sort based on the score
        results.sort(key=lambda x: x[1])
        # filter()

        # 
        # if len(results):
        mappings.update({main: results})

    return mappings


