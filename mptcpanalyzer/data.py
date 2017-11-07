#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import pandas as pd
import numpy as np
from mptcpanalyzer.tshark import TsharkConfig, Filetype
# from mptcpanalyzer.config import MpTcpAnalyzerConfig, get_config
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection
import mptcpanalyzer as mp
from mptcpanalyzer import get_config, get_cache, Destination
from typing import List, Any, Tuple, Dict, Callable, Collection
import math
import tempfile

log = logging.getLogger(__name__)
slog = logging.getLogger(__name__)

# todo rename to mapper ?

"""
Used when dealing with the merge of dataframes
"""
suffixes = ("_h1", "_h2")


def ignore(f1, f2):
    return 0


def exact(f1, f2):
    # print("comparing values ", f1, " and ", f2)
    return 10 if (math.isnan(f1) and math.isnan(f2)) or f1 == f2 else float('-inf')


def diff(f1, f2):
    return f2 - f1


def debug_convert(df):
    return df.head(20)
    # return df


"""
invariant: True if not modified by the network
Of the form Field.shortname

Have a look at the graphic slide 28:
https://www-phare.lip6.fr/cloudnet12/Multipath-TCP-tutorial-cloudnet.pptx

TODO add it to Field ?
"""
scoring_rules = {
    "packetid": ignore,
    # in-order packets are more common than out of order ones
    "abstime": diff,
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


# def load_from_cache(input_file,):
#     cache = mp.get_cache()

# def load_into_pandas(
#         ):

def load_into_pandas(
    input_file: str,
    config: TsharkConfig,
    dependencies: Collection =[], # TODO remove 
    # load_cb = load_pcap_into_pandas,
    regen: bool=False,
    **extra
    # metadata: Metadata=Metadata(), # passer une fct plutot qui check validite ?
) -> pd.DataFrame:
    """
    load mptpcp data into pandas

    Args:
        input_file: pcap filename
        config: Hard, keep changing
        load_cb: callback to use if cache not available
        extra: extra arguments to forward to load_cb
        regen: Ignore the cache and regenerate any cached csv file from the input pcap
    """
    log.debug("Asked to load %s" % input_file)

    # TODO get the real path and use it in hash ?
    filename = os.path.expanduser(input_file)
    filename = os.path.realpath(filename)
    cache = mp.get_cache()

    # csv_filename = self.get_matching_csv_filename(filename, regen)
    # if os.path.isfile(cachename):
    uid = cache.cacheuid(
        # filename,  # prefix (might want to shorten it a bit)
        '',
        dependencies,
        str(config.hash())  + '.csv'
    )

    # try:
    is_cache_valid, csv_filename = cache.get(uid)

    # except:
    #     log.info("Cache invalid... Converting %s into %s" % (filename,))

    # is_cache_valid, csv_filename = cache.is_cache_valid(uid, )

    log.debug("valid cache: %d cachename: %s" % (is_cache_valid, csv_filename))
    if regen or not is_cache_valid:
        log.info("Cache invalid... Converting %s " % (filename,))

        with tempfile.NamedTemporaryFile(mode='w+', prefix="mptcpanalyzer-", delete=False) as out:
            retcode, stderr = config.export_to_csv(
                filename,
                # csv_filename,
                out,
                config.get_fields("fullname", "name"),
            )
            log.info("exporter exited with code=%d", retcode)
            if retcode is 0:
                out.close()
                cache.put(uid, out.name)
            else:
                # remove invalid cache log.exception
                # os.remove(csv_filename)
                raise Exception(stderr)

    # print("CONFIG=", cfg)

    temp = config.get_fields("fullname", "type")
    dtypes = {k: v for k, v in temp.items() if v is not None}
    log.debug("Loading a csv file %s" % csv_filename)

    with open(csv_filename) as fd:
        # first line is metadata
        # TODO: creer classe metadata read/write ?
        # metadata = fd.readline()

        data = pd.read_csv(
            fd,
            # skip_blank_lines=True,
            # hum not needed with comment='#'
            comment='#',
            # we don't need 'header' when metadata is with comment
            # header=mp.METADATA_ROWS, # read column names from row 2 (before, it's metadata)
            # skiprows
            sep=config.delimiter,
            dtype=dtypes,
            converters={
                "tcp.flags": lambda x: int(x, 16),
                # reinjections, converts to list of integers
                "mptcp.duplicated_dsn": lambda x: list(map(int, x.split(','))) if x else np.nan,
                # "mptcp.related_mapping": lambda x: x.split(','),
            },
            # memory_map=True, # could speed up processing
        )
        # TODO:
        # No columns to parse from file
        data.rename(inplace=True, columns=config.get_fields("fullname", "name"))
        log.debug("Column names: %s", data.columns)

    # pp = pprint.PrettyPrinter(indent=4)
    # log.debug("Dtypes after load:%s\n" % pp.pformat(data.dtypes))
    return data


def pandas_to_csv(df: pd.DataFrame, filename, **kwargs):
    config = mp.get_config()
    return df.to_csv(
        filename,  # output
        # columns=self.columns,
        # how do we get the config
        sep=config["mptcpanalyzer"]["delimiter"],
        # index=True, # hide Index
        header=True,  # add
        **kwargs
    )


def merge_tcp_dataframes(
    df1: pd.DataFrame, df2: pd.DataFrame,
    df1_tcpstream: int
) -> pd.DataFrame:
    """
    First looks in df2 for a  tcpstream matching df1_tcpstream
    """
    log.debug("Merging TCP dataframes ")  # % ( df1))
    main_connection = TcpConnection.build_from_dataframe(df1, df1_tcpstream)

    # du coup on a une liste
    mappings = map_tcp_stream(df2, main_connection)

    print("Found mappings %s" % mappings)
    if len(mappings) <= 0:
        print("Could not find a match in the second pcap for tcpstream %d" % df1_tcpstream)
        return

    print("len(df1)=", len(df1), " len(rawdf2)=", len(df2))
    mapped_connection, score = mappings[0]
    print("Found mappings %s" % mappings)
    for con, score in mappings:
        print("Con: %s" % (con))

    return merge_tcp_dataframes_known_streams(
        (df1, main_connection),
        (df2, mapped_connection)
    )


def generate_columns(to_add: List[str], to_delete: List[str], suffixes) -> List[str]:
    """
    Generate column names
    """

    # columns =
    return [
        "owd",
        "abstime" + suffixes[0],
        "abstime" + suffixes[1],
        "packetid" + suffixes[0],
        "packetid" + suffixes[1],
        "ipsrc" + suffixes[0],
        "ipsrc" + suffixes[1],
        "ipdst" + suffixes[0],
        "ipdst" + suffixes[1],
        "sport" + suffixes[0],
        "sport" + suffixes[1],
        "dport" + suffixes[0],
        "dport" + suffixes[1],
        "tcpseq"
    ]


combo = Tuple[pd.DataFrame, TcpConnection]


# TODO use named tuples ?
def merge_tcp_dataframes_known_streams(
    con1: Tuple[pd.DataFrame, TcpConnection],
    con2: Tuple[pd.DataFrame, TcpConnection]
) -> pd.DataFrame:
    """
    TODO should I return a merged df order in which

    Generates an intermediate file with the owds.

    1/ identify which dataframe is server's/client's
    2/

    Args:
        con1: Tuple dataframe/tcpstream id
        con2: same

    Returns:
        res
        To ease debug we want to see packets in chronological order

    """
    h1_df, main_connection = con1
    h2_df, mapped_connection = con2
    cfg = get_config()

    # limit number of packets while testing
    # HACK to process faster
    h1_df = debug_convert(h1_df)
    h2_df = debug_convert(h2_df)


    # print(h1_df["abstime"].head())
    # print(h1_df.head())
    # should be sorted, to be sure we could use min() but more costly
    # min_h1 = h1_df.loc[0,'abstime']
    # min_h2 = h2_df.loc[0,'abstime']
    # # min
    # if min_h1 < min_h2:
    #     print("Looks like h1 is the sender")
    #     client_df = h1_df
    #     receiver_df = h2_df
    # else:
    #     print("Looks like h2 is the sender")
    #     client_df = h2_df
    #     receiver_df = h1_df

    min_h1 = h1_df['abstime'].min()
    min_h2 = h2_df['abstime'].min()
    # min
    if min_h1 < min_h2:
        print("Looks like h1 is the client")
        client_con, server_con = con1, con2
        # client_df, client_con = h1_df, main_connection
        # server_df, server_con = h2_df, mapped_connection
        # suffixes = ('_h1', '_h2')
    else:
        print("Looks like h2 is the client")
        client_con, server_con = con2, con1
        # client_df = h2_df
        # server_df = h1_df
        # suffixes = ('_h2', '_h1')


    print("Mapped connection %s to %s" % (mapped_connection, main_connection))

    # print("Delimiter:", sep=cfg["mptcpanalyzer"]["delimiter"])

    # filename = "merge_%d_%d.csv" % (tcpstreamid_host0, tcpstreamid_host1)
    # TODO reorder columns to have packet ids first !

    columns = generate_columns([], [], suffixes)
    total = None  #  pd.DataFrame()
    for dest in Destination:

        q = server_con[1].generate_direction_query(dest)
        server_unidirectional_df = server_con[0].query(q)
        q = client_con[1].generate_direction_query(dest)
        client_unidirectional_df = h2_df.query(q)

        if dest == Destination.Client:
            sender_df, receiver_df = server_unidirectional_df, client_unidirectional_df
        else:
            # destination is server
            sender_df, receiver_df = server_unidirectional_df, client_unidirectional_df

        res = generate_tcp_directional_owd_df(sender_df, receiver_df, dest)
        res['tcpdest'] = dest.name
        total = pd.concat([res, total])

        # TODO remove in the future (and / or use specific export fct)
        filename = "merge_%d_%s.csv" % (main_connection.tcpstreamid, dest)
        res.to_csv(
            filename, # output
            columns=columns,
            # how do we get the config
            sep=cfg["mptcpanalyzer"]["delimiter"],
            # index=True, # hide Index
            header=True,  # add
            # sep=main.config["DEFAULT"]["delimiter"],
        )


    # TODO move elsewhere, to outer function
    # firstcols = ['packetid_h1', 'packetid_h2', 'dest', 'owd']
    # total = total.reindex(columns=firstcols + list(filter(lambda x: x not in firstcols, total.columns.tolist())))
    # total.to_csv(
    #     cachename, # output
    #     # columns=self.columns,
    #     index=False,
    #     header=True,
    #     # sep=main.config["DEFAULT"]["delimiter"],
    # )
    return total


def merge_mptcp_dataframes(
    df1: pd.DataFrame, df2: pd.DataFrame,
    df1_mptcpstream: int
) -> pd.DataFrame:
    """
    First looks in df2 for a stream matching df1_mptcpstream

    See:
        merge_mptcp_dataframes_known_streams
    """
    # df1, df2 = dataframes
    main_connection = MpTcpConnection.build_from_dataframe(df1, df1_mptcpstream)

    # du coup on a une liste
    mappings = mptcp_match_connection(df2, main_connection)

    # print("Found mappings %s" % mappings)
    # returned a dict
    # if mptcpstream not in mappings:
    #     print("Could not find ptcpstream %d in the first pcap" % mptcpstream)
    #     return
    # print("Number of %d" % len(mappings[mptcpstream]))
    # print("#mappings=" len(mappings):
    if len(mappings) <= 0:
        # TODO throw instead
        # raise Exception
        print("Could not find a match in the second pcap for mptcpstream %d" % df1_mptcpstream)
        return

    # print("len(df1)=", len(df1), " len(rawdf2)=", len(rawdf2))
    # mappings
    mapped_connection, score = mappings[0]


    # try:
    #     idx = mapped_connection.subflows.index(sf)
    #     sf2 = mapped_connection.subflows[idx]
    #     common_subflows.append((sf, sf2))

    # except ValueError:
    #     continue

    # main_connection = TcpConnection.build_from_dataframe(df1, df1_mptcpstream)

    # # du coup on a une liste
    # mappings = map_tcp_stream(df2, main_connection)

    print("Found mappings %s" % mappings)
    if len(mappings) <= 0:
        print("Could not find a match in the second pcap for tcpstream %d" % df1_mptcpstream)
        return

    print("len(df1)=", len(df1), " len(rawdf2)=", len(df2))
    mapped_connection, score = mappings[0]
    print("Found mappings %s" % mappings)
    for con, score in mappings:
        print("Con: %s" % (con))

    return merge_mptcp_dataframes_known_streams(
        (df1, main_connection),
        (df2, mapped_connection)
    )


def merge_mptcp_dataframes_known_streams(
    con1: Tuple[pd.DataFrame, MpTcpConnection],
    con2: Tuple[pd.DataFrame, MpTcpConnection]
) -> pd.DataFrame:
    """
    Useful for reinjections etc...

    :see: .merge_mptcp_dataframes


    Returns:
        Per-subflow dataframes
        See .merge_tcp_dataframes_known_streams for in

        I want to see packets leave as
    """
    # mptcpdest=
    main_connection, df1 = con1
    mapped_connection, df2 = con2
    # Keep subflows that are present in the two connections (useless anyway ?)
    common_subflows = []
    for sf in main_connection.subflows:
        # if sf2 in
        for sf2 in mapped_connection.subflows:
            if sf == sf2:
                common_subflows.append((sf, sf2))
                break


    # TODO when looking into the cache, check for mptcpstream
    # prepare metadata
    #

    # for subflow in common_subflows:
    #     merge_tcp_dataframes_known_streams()




# def generate_tcp_bidirectional_owd_df(
#         self, h1_df, h2_df, **kwargs):
#     """
#     """
#     total = None # pd.DataFrame()
#     for dest in mp.Destination:
#         q = main_connection.generate_direction_query(dest)
#         h1_directional_df = h1_df.query(q)
#         q = mapped_connection.generate_direction_query(dest)
#         h2_directional_df = h2_df.query(q)

#         # returns directional packetid <-> mapped
#         res = self.generate_tcp_directional_owd_df(client_directional, local_receiver_df, dest)
#         # res['dest'] = dest
#         total = pd.concat([res, total])

#         # kept for debug
#         filename = "merge_%d_%s.csv" % (mptcpstream, dest)
#         res.to_csv(
#             filename, # output
#             columns=self.columns,
#             index=True,
#             header=True,
#             # sep=main.config["DEFAULT"]["delimiter"],
#         )


# TODO faire une fonction pour TCP simple
def generate_tcp_directional_owd_df(
    # todo
    # h1_df, h2_df,
    sender_df, receiver_df,
    dest,
    suffixes=('_sender', '_receiver'),
    **kwargs
):
    """
    Generate owd in one sense
    sender_df and receiver_df must be perfectly cleaned beforehand

    Attr:
        suffixes:

    Returns
    """
    log.info("Generating intermediary results")
    # assert len(h1_df.groupby()) == 1
    assert len(suffixes) == 2, "Should be 2 elements for host1 and host2"

    # this will return rawdf1 with an aditionnal "mapped_index" column that
    # correspond to
    toexplain = [ 20 ]
    mapped_df = map_tcp_packets(sender_df, receiver_df, toexplain)

    # on sender_id = receiver_mapped_packetid

    # TODO print statistics about how many packets have been mapped
    # print(" len(mapped_df)")
    # should print packetids

    print("== DEBUG START ===")
    print("Mapped index:")
    print(mapped_df[["rcv_pktid", "packetid"]].head())
    # print(mapped_df[["abstime", "tcpseq", "sendkey"]].head())
    # print(mapped_df[["abstime", "tcpseq", "sendkey"]].head())
    print("== DEBUG END ===")

    # we don't want to
    # on veut tjrs avoir le mapping
    # if dest == Destination.Server:
    res = pd.merge(
        mapped_df, receiver_df,
        left_on="rcv_pktid",
        right_on="packetid",
        # right_index=True,
        # TODO en fait suffit d'inverser les suffixes, h1, h2
        suffixes=suffixes, # how to suffix columns (sender/receiver)
        how="inner", #
        indicator=True # adds a "_merge" suffix
    )

    newcols = {
        'score' + suffixes[0]: 'score',
    }
    res.rename(columns=newcols, inplace=True)

    # need to compute the owd depending on the direction right
    # if dest == Destination.Server:
    res['owd'] = res['abstime' + suffixes[1]] - res['abstime' + suffixes[0]]
    # res['owd'] = client_df[ mapped_df["receiver_pktid"],'abstime'] - server_df[mapped_df['sender_pktid'], 'abstime']

    print("unidirectional results\n", res.head())
    # print(res[["packetid", "mapped_index", "owd", "sendkey_snd", "sendkey_rcv"]])
    return res



def map_tcp_packet(df, packet, explain=False) -> List[Tuple[Any, float]]: # Tuple(row, score)
    # instead should be index ?
    """
    Packets may disappear, get retransmitted

    Args:
        packet:

    Returns:
        a list of tuples (index, score)
    """

    def _get_pktid(row) -> int:
        return row.packetid
    # used to be row.Index when df.set_index("packetid") was in use

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
                if explain:
                    log.debug("comparing pktids %d with %d for field %s" % (_get_pktid(packet), _get_pktid(row), field))
                f1 = getattr(p1, field)
                f2 = getattr(p2, field)
                score += scoring_rules[field](f1, f2)
                # log.debug("new score after column [%s] = %f" % (field, score))
                if math.isinf(score):
                    if explain:
                        log.debug("Score set to infinity for field %s" % field)
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
            log.debug("packet %d mapped to %d with a score of %d" % (_get_pktid(packet), _get_pktid(row), score))
            scores.append((_get_pktid(row), score))
        else:
            log.debug("Found no match for pktid %d, skipping.." % _get_pktid(packet))

    # sort by score
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores


def map_tcp_packets(
    sender_df, receiver_df,
    explain=[] 
        # con1: TcpConnection, con2: TcpConnection
) -> pd.DataFrame:
    """
    Stream ids must already mapped
    Args:
        explain = increase verbosity for packet ids in this list

    Todo:
        check N = len(sender_df) - len(receiver_df) to know how many packets should be missing,
        then cut off lowest N.

    algo:
        Computes a score on a per packet basis
        Based

    Returns:
        a copy of sender_df with as Index the packetid + a new column called
        "mapped_index" matching the Index of rawdf2
        'rcv_pktid', 'score'
    """
    # DataFrame.add(other, axis='columns', level=None, fill_value=None)
    # adds a new column that contains only nan
    log.debug("Mapping TCP packets between TODO")

    # returns a new df with new columns rcv_pktid, score initialized to NaN
    df_final = sender_df.assign(rcv_pktid=np.nan, score=np.nan,)

    # # Problem is to identify lost packets and retransmitted ones
    # # so that they map to the same or none ?
    limit = 5  # limit nb of scores to display

    # df_res = pd.DataFrame(columns=['packetid', 'score', "mapped_rcvpktid"])
    for row in sender_df.itertuples():

        explain_pkt = row.packetid in explain
        scores = map_tcp_packet(receiver_df, row, explain_pkt)
        print("first %d packets (pandas.index/score)s=\n%s" % (limit, scores[:limit]))
        # takes best score index
        # print("row=", df_final.loc[row.index, "packetid"])
        # df_final.loc[row.index , 'mapped_index'] = 2 # scores[0][0]
        # print(type(row.Index), type(row.index))
        if len(scores) >= 1:
            if explain_pkt:
                for idx, score in scores:
                    log.debug("Score %s=%s" % (idx, score))
            idx, score = scores[0]

            df_final.set_value(row.Index, 'rcv_pktid', idx)
            df_final.set_value(row.Index, 'score', score)
            # TODO we might want to remove that packets from further search

        # drop the chosen index so that it doesn't get used a second time
        # todo pb la c qu'on utilise les packet id comme des index :/
            print("Score %f assigned to index %s" % (score, idx))
            # df2.drop(df2.index[[idx]], inplace=True)
            # df2.drop(idx, inplace=True)
        else:
            log.debug("No map found for this packet")

        # print("registered = %s" % ( df_final.loc[row.Index, 'mapped_index'])) # , ' at index: ', row.index )

    # print("head=\n", df_final.head())
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


def map_tcp_stream(rawdf: pd.DataFrame, main: TcpConnection) -> List[Tuple[TcpConnection, int]]:
    """
    Returns:
        a list of tuple (
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
    results = []  # type: List[Tuple[Any, float]]

    mappings = {}  # type: Dict[int,Tuple[Any, float]]

    # main = MpTcpConnection.build_from_dataframe(df, mptcpstream)
    score = -1  # type: float
    results = []

    for mptcpstream2 in rawdf2["mptcpstream"].unique():
        other = MpTcpConnection.build_from_dataframe(rawdf2, mptcpstream2)
        score = main.score(other)
        if score > float('-inf'):
            results.append((other, score))

    # sort based on the score
    results.sort(key=lambda x: x[1], reverse=True)

    return results
