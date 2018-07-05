import logging
import os
import pandas as pd
import numpy as np
from mptcpanalyzer.tshark import TsharkConfig
from mptcpanalyzer.connection import MpTcpSubflow, MpTcpConnection, TcpConnection, MpTcpMapping, TcpMapping
import mptcpanalyzer as mp
from mptcpanalyzer import RECEIVER_SUFFIX, SENDER_SUFFIX, _receiver, _sender, suffix_fields
from mptcpanalyzer import get_config, get_cache, ConnectionRoles
from typing import List, Any, Tuple, Dict, Callable, Collection, Union
import math
import tempfile
import pprint
import functools
from enum import Enum

log = logging.getLogger(__name__)
slog = logging.getLogger(__name__)

pp = pprint.PrettyPrinter(indent=4)

# dtype_role = pd.api.types.CategoricalDtype(categories=ConnectionRoles, ordered=True)
dtype_role = pd.api.types.CategoricalDtype(categories=[ x.name for x in ConnectionRoles], ordered=True)


# columns we usually display to debug dataframes
# def _receiver(fields):
#     return list(map(lambda x: x + RECEIVER_SUFFIX, fields))

# def _sender(fields):
#     return list(map(lambda x: x + SENDER_SUFFIX, fields))

TCP_DEBUG_FIELDS=['hash', 'packetid', "reltime", "abstime"]
# 'tcpdest'
MPTCP_DEBUG_FIELDS=TCP_DEBUG_FIELDS + [ 'mptcpdest']



def ignore(f1, f2):
    return 0


def exact(f1, f2):
    return 10 if (math.isnan(f1) and math.isnan(f2)) or f1 == f2 else float('-inf')


def diff(f1, f2):
    return f2 - f1


def debug_convert(df):
    return df
    # return df.head(20)


def getrealpath(input_file):
    filename = os.path.expanduser(input_file)
    filename = os.path.realpath(filename)
    return filename

def _convert_flags(x):
    return int(x, 16)

def _convert_to_list(x, field="pass a field to debug"):
    """
    Loads x of the form "1,2,5" or None
    for instance functools.partial(_convert_to_list, field="reinjectionOf"),
    returns np.nan instead of [] to allow for faster filtering
    """
    # pandas error message are not the best to understand why the convert failed
    # so we use this instead of lambda for debug reasons
    # print("converting field %s with value %r" % (field, x))
    res = list(map(int, x.split(','))) if (x is not None and x != '') else np.nan
    return res

def _convert_list2str(serie):
    """
    """
    # copy=False
    return serie.astype(str, ).str.strip('[]').str.replace('\s+', '')

"""
when trying to map packets from a pcap to another, we give a score to each mapping
based on per-field rules.

invariant: True if not modified by the network
Of the form Field.shortname

Have a look at the graphic slide 28:
https://www-phare.lip6.fr/cloudnet12/Multipath-TCP-tutorial-cloudnet.pptx

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
}

hashing_fields = [
    "ipsrc",
    "ipdst",
    "sport",
    "dport",
    "tcpack",
    "tcptsval",
    "tcptsecr",
    # "expected_token",
    "sport",
    "dport",
    "rwnd",
    "sendkey",
    "recvkey",
    "recvtok",
    "tcpflags",
    "dss_dsn",
    "dss_rawack",
    "dss_ssn",
    "tcpseq",
    "tcplen"
]

class PacketMappingMode(Enum):
    """
    How to map packets from one stream to another

    The SCORE based algorithm allows to work with traffic that went trhoug NATs 
    etc but is buggy/less tested

    The hash based is more straightforward
    """
    HASH = 1
    SCORE = 2



def load_merged_streams_into_pandas(
    pcap1: str,
    pcap2: str,
    streamid1: int, # Union[MpTcpStreamId, TcpStreamId],
    streamid2: int,
    mptcp: bool, 
    tshark_config: TsharkConfig,
    mapping_mode: PacketMappingMode = PacketMappingMode.HASH,
    **extra
    ):
    """
    Arguments:
        protocol: mptcp or tcp

    Returns
        a dataframe with columns... owd ?
    """
    log.debug("Asked to load merged tcp streams %d and %d from pcaps %s and %s" 
            % (streamid1, streamid2, pcap1, pcap2)
    )

    
    # mp.get_config()
    # tshark_config = TsharkConfig()
    cache = mp.get_cache()
    protocolStr = "mptcp" if mptcp else "tcp"
    # merged_uid
    cacheid = cache.cacheuid("merged", [
        getrealpath(pcap1),
        getrealpath(pcap2),
        ], 
        protocolStr + "_" + str(streamid1) + "_" + str(streamid2) + ".csv")

    # if we can't load that file from cache
    try:
        cache = mp.get_cache()
        merged_df = pd.DataFrame()

        valid, cachename = cache.get(cacheid)
        log.info("Cache validity=%s and cachename=%s" % (valid, cachename))

        if not valid:
            df1 = load_into_pandas(pcap1, tshark_config,)
            df2 = load_into_pandas(pcap2, tshark_config,)

            main_connection  = None # type: Union[MpTcpConnection, TcpConnection]
            other_connection = None # type: Union[MpTcpConnection, TcpConnection]
            if mptcp:
                main_connection = MpTcpConnection.build_from_dataframe(df1, streamid1)
                other_connection = MpTcpConnection.build_from_dataframe(df2, streamid2)

                # TODO generate
                # map_mptcp_connection()

                # for now we use known streams exclusively
                # might be interested to use merge_tcp_dataframes later
                merged_df = merge_mptcp_dataframes_known_streams(
                    (df1, main_connection),
                    (df2, other_connection)
                )

            else:
                main_connection = TcpConnection.build_from_dataframe(df1, streamid1)
                other_connection = TcpConnection.build_from_dataframe(df2, streamid2)

                # for now we use known streams exclusively
                # might be interested to use merge_tcp_dataframes later
                merged_df = merge_tcp_dataframes_known_streams(
                    (df1, main_connection),
                    (df2, other_connection)
                )

            # TODO assert merged_df is not null
            # firstcols = [ 'packetid_sender', 'packetid_receiver', 'owd']
            # total = total.reindex(columns=firstcols + list(filter(lambda x: x not in firstcols, total.columns.tolist())))
            assert cachename
            log.info("Saving into %s" % cachename)
            # merged_df.A.astype(str).str.strip('[]').str.replace('\s+', '')
            # trying to export lists correctly
            # merged_df.reinjected_of = _convert_list2str(merged_df.reinjected_of)
            # merged_df.reinjected_in = _convert_list2str(merged_df.reinjected_in)
            # print("REINJECTED_IN")
            # print(merged_df.reinjected_in.dropna().head())
            merged_df.to_csv(
                cachename,
                # columns=columns,
                index=False,
                header=True,
                sep=tshark_config.delimiter,
            )

            print("MATT=", dict(merged_df.dtypes))

            # print("MERGED_DF", merged_df[TCP_DEBUG_FIELDS].head(20))


        else:
            log.info("Loading from cache %s" % cachename)
            csv_fields = tshark_config.get_fields("name", "type")
            # dtypes = {k: v for k, v in temp.items() if v is not None or k not in ["tcpflags"]}
            def _gen_dtypes(fields):
                dtypes = {} # type: ignore
                for suffix in [ SENDER_SUFFIX, RECEIVER_SUFFIX]:

                    for k, v in fields.items():
                        if v is not None or k not in ["tcpflags"]:
                            dtypes.setdefault(suffix_fields(suffix, k), v)

                dtypes.update({
                    # during the merge, we join even unmapped packets so some entries
                    # may be empty => float64
                    _sender("packetid"): np.float64,
                    _receiver("packetid"): np.float64,
                    # there is a bug currently
                    # https://github.com/pandas-dev/pandas/pull/20826
                    'mptcpdest': dtype_role,
                    'tcpdest': dtype_role,
                    # '_merge': 
                })
                return dtypes

            def _load_list(x, field="set field to debug"):
                """
                Contrary to _convert_to_list
                """
                res = ast.literal_eval(x) if (x is not None and x != '') else np.nan
                return res

            def _convert_role(x):
                """
                Workaround https://github.com/pandas-dev/pandas/pull/20826
                """
                return ConnectionRoles[x] if x else np.nan

            with open(cachename) as fd:
                import ast
                dtypes = _gen_dtypes(csv_fields)

                # more recent versions can do without it
                # pd.set_option('display.max_rows', 200)
                # pd.set_option('display.max_colwidth', -1)
                print("dtypes=", dict(dtypes))
                merged_df = pd.read_csv(
                    fd,
                    skip_blank_lines=True,
                    # hum not needed with comment='#'
                    comment='#',
                    # we don't need 'header' when metadata is with comment
                    # header=0, # read column names from row 2 (before, it's metadata)
                    # skiprows
                    sep=tshark_config.delimiter,
                    # converters={
                    #     "tcp.flags": lambda x: int(x, 16),
                    #     # reinjections, converts to list of integers
                    #     # "mptcp.related_mapping": lambda x: x.split(','),
                    # },
                    # memory_map=True, # could speed up processing
                    # Categorical for TcpDest / mptcpdest
                    dtype=dtypes, # poping still generates
                    converters={
                        _sender("tcpflags"): _convert_flags,
                        # reinjections, converts to list of integers
                        _sender("reinjection_of"): functools.partial(_load_list, field="reinjectedOfSender"),
                        _sender("reinjected_in"): functools.partial(_load_list, field="reinjectedInSender"),
                        _receiver("reinjection_of"): functools.partial(_load_list, field="reinjectedInReceiver"),
                        _receiver("reinjected_in"): functools.partial(_load_list, field="reinjectedInReceiver"),

                        # there is a bug in pandas see https://github.com/pandas-dev/pandas/pull/20826
                        # where the 
                        "mptcpdest": _convert_role,
                        "tcpdest": _convert_role,

                        # "mptcp.reinjection_of": functools.partial(_convert_to_list, field="reinjectionOf"),
                        # "mptcp.reinjection_listing": functools.partial(_convert_to_list, field="reinjectedIn"),
                        # "mptcp.reinjected_in": functools.partial(_convert_to_list, field="reinjectedIn"),
                        # "mptcp.duplicated_dsn": lambda x: list(map(int, x.split(','))) if x is not None else np.nan,
                    },
                )

                # log.debug("Column names after loading from cache: %s", merged_df.columns)

                # TODO:
                # No columns to parse from file
                # data.rename(inplace=True, columns=config.get_fields("fullname", "name"))

    except Exception:
        log.exception("exception happened")

    finally:
        log.debug("Column names: %s", merged_df.columns)
        # pd.set_option('display.max_rows', 200)
        # pd.set_option('display.max_colwidth', -1)
        # print("dtypes=", dict(dtypes))
        # log.debug("Dtypes after load:%s\n" % pp.pformat(merged_df.dtypes))
        log.debug("Dtypes after load:%s\n" % dict(merged_df.dtypes))
        log.info("Finished loading. merged dataframe size: %d" % len(merged_df))

        return merged_df


def load_into_pandas(
    input_file: str,
    config: TsharkConfig,
    regen: bool=False,
    gen_hash: bool=True,
    **extra
) -> pd.DataFrame:
    """
    load mptcp  data into pandas

    Args:
        input_file: pcap filename
        config: Hard, keep changing
        load_cb: callback to use if cache not available
        extra: extra arguments to forward to load_cb
        regen: Ignore the cache and regenerate any cached csv file from the input pcap
    """
    log.debug("Asked to load simple pcap %s" % input_file)

    filename = getrealpath(input_file)
    cache = mp.get_cache()

    uid = cache.cacheuid(
        '',  # prefix (might want to shorten it a bit)
        [ filename ], # dependencies
        str(config.hash())  + '.csv'
    )

    is_cache_valid, csv_filename = cache.get(uid)

    log.debug("cache validity=%d cachename: %s" % (is_cache_valid, csv_filename))
    if regen or not is_cache_valid:
        log.info("Cache invalid or ignored(=%s)... Converting %s " % (regen, filename,))

        with tempfile.NamedTemporaryFile(mode='w+', prefix="mptcpanalyzer-", delete=False) as out:
            retcode, stderr = config.export_to_csv(
                filename,
                out,
                config.get_fields("fullname", "name"),
            )
            log.info("exporter exited with code=%d", retcode)
            if retcode is 0:
                out.close()
                cache.put(uid, out.name)
            else:
                raise Exception(stderr)

    temp = config.get_fields("fullname", "type")
    dtypes = {k: v for k, v in temp.items() if v is not None or k not in ["tcpflags"]}
    log.debug("Loading a csv file %s" % csv_filename)

    try:
        with open(csv_filename) as fd:

            data = pd.read_csv(
                fd,
                comment='#',
                sep=config.delimiter,
                # having both a converter and a dtype for a field generates warnings
                # so we pop tcp.flags
                # dtype=dtypes.pop("tcp.flags"),
                dtype=dtypes, # poping still generates
                converters={
                    "tcp.flags": _convert_flags,
                    # reinjections, converts to list of integers
                    "mptcp.reinjection_of": functools.partial(_convert_to_list, field="reinjectionOf"),
                    "mptcp.reinjected_in": functools.partial(_convert_to_list, field="reinjectedIn"),
                },
                # nrows=10, # useful for debugging purpose
            )
            data.rename(inplace=True, columns=config.get_fields("fullname", "name"))
            # we want packetid column to survive merges/dataframe transformation so keepit as a column
            # TODO remove ? let other functions do it ?
            data.set_index("packetid", drop=False, inplace=True)
            log.debug("Column names: %s", data.columns)

            if gen_hash:
                # generate a hash to map packets from one pcap to another
                # filter
                hash_list = []
                for name, rule in scoring_rules.items():
                    if rule == exact:
                        hash_list.append(name)
                        
                log.debug("Hashing over fields %s" % hash_list)

                # won't work because it passes a Serie (mutable)_
                temp = pd.DataFrame(data, columns=hashing_fields)
                        # [['expected_token', 'sport', 'dport', 'rwnd', 'sendkey',  'tcpflags', 'dss_dsn', 'dss_rawack', 'dss_ssn', 'tcpseq', 'tcplen' ]]
                data["hash"] = temp.apply(lambda x: hash(tuple(x)), axis = 1)

    except Exception as e:
        logging.error("You may need to filter more your pcap to keep only mptcp packets")
        raise e

    log.info("Finished loading dataframe for %s. Size=%d" % (input_file, len(data)))
    return data


def pandas_to_csv(df: pd.DataFrame, filename, **kwargs):
    config = mp.get_config()
    return df.to_csv(
        filename,
        sep=config["mptcpanalyzer"]["delimiter"],
        header=True,
        **kwargs
    )


# TODO should be made more programmatic
def merge_tcp_dataframes(
    df1: pd.DataFrame, df2: pd.DataFrame,
    df1_tcpstream: int
) -> pd.DataFrame:
    """
    First looks in df2 for a  tcpstream matching df1_tcpstream
    """
    log.debug("Merging TCP dataframes ")
    main_connection = TcpConnection.build_from_dataframe(df1, df1_tcpstream)

    mappings = map_tcp_stream(df2, main_connection)

    print("Found mappings %s" % mappings)
    if len(mappings) <= 0:
        print("Could not find a match in the second pcap for tcpstream %d" % df1_tcpstream)
        return

    print("len(df1)=", len(df1), " len(rawdf2)=", len(df2))
    mapped_connection = mappings[0].mapped
    print("Found mappings %s" % mappings)
    for mapping in mappings:
        print("Con: %s" % (mapping.mapped))

    return merge_tcp_dataframes_known_streams(
        (df1, main_connection),
        (df2, mapped_connection)
    )


def generate_columns(to_add: List[str], to_delete: List[str], suffixes) -> List[str]:
    """
    Generate column names
    """
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


def merge_tcp_dataframes_known_streams(
    con1: Tuple[pd.DataFrame, TcpConnection],
    con2: Tuple[pd.DataFrame, TcpConnection]
    # , dest: ConnectionRoles
) -> pd.DataFrame:
    """
    Generates an intermediate file with the owds.

    1/ clean up dataframe to keep
    2/ identify which dataframe is server's/client's
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

    # cleanup the dataframes to contain only the current stream packets
    h1_df = h1_df[ h1_df.tcpstream == main_connection.tcpstreamid]
    h2_df = h2_df[ h2_df.tcpstream == mapped_connection.tcpstreamid]

    min_h1 = h1_df['abstime'].min()
    min_h2 = h2_df['abstime'].min()
    log.debug("Comparing %f (h1) with %f (h2)" % (min_h1, min_h2))
    if min_h1 < min_h2:
        log.debug("Looks like h1 is the client")
        client_con, server_con = con1, con2
    else:
        log.debug("Looks like h2 is the client")
        client_con, server_con = con2, con1


    log.info("Trying to merge connection {} to {} of respective sizes {} and {}".format(
        mapped_connection, main_connection, len(h1_df), len(h2_df)
    ))
    # print(h1_df[["packetid","hash", "reltime"]].head(5))
    # print(h2_df[["packetid","hash", "reltime"]].head(5))

    # TODO reorder columns to have packet ids first !

    # columns = generate_columns([], [], suffixes)
    total = None  #  pd.DataFrame()
    for dest in ConnectionRoles:

        log.debug("Looking at destination %s" % dest)
        q = server_con[1].generate_direction_query(dest)
        server_unidirectional_df = server_con[0].query(q)
        q = client_con[1].generate_direction_query(dest)
        client_unidirectional_df = client_con[0].query(q)

        if dest == ConnectionRoles.Client:
            sender_df, receiver_df = server_unidirectional_df, client_unidirectional_df
        else:
            # destination is server
            sender_df, receiver_df =  client_unidirectional_df, server_unidirectional_df

        # TODO we don't necessarely need to generate the OWDs here, might be put out
        res = generate_tcp_directional_owd_df(sender_df, receiver_df, dest)
        res['tcpdest'] = dest.name
        total = pd.concat([res, total])

    # TODO move elsewhere, to outer function
    # total = total.reindex(columns=firstcols + list(filter(lambda x: x not in firstcols, total.columns.tolist())))
    # total.to_csv(
    #     cachename, # output
    #     # columns=self.columns,
    #     index=False,
    #     header=True,
    #     # sep=main.config["DEFAULT"]["delimiter"],
    # )
    log.info("Resulting merged tcp dataframe of size {} (to compare with {} and {})".format(
        len(total), len(h1_df), len(h2_df)
    ))

    
    return total


# TODO make it part of the api (aka no print) or remove it ?
def merge_mptcp_dataframes(
    df1: pd.DataFrame, df2: pd.DataFrame,
    df1_mptcpstream: int
    ) -> Tuple[pd.DataFrame, str]:
    """
    First looks in df2 for a stream matching df1_mptcpstream

    See:
        merge_mptcp_dataframes_known_streams
    """
    main_connection = MpTcpConnection.build_from_dataframe(df1, df1_mptcpstream)

    # we map over df2
    mappings = map_mptcp_connection(df2, main_connection)

    print("Found mappings %s" % (mappings,))

    if len(mappings) <= 0:
        # TODO throw instead
        # raise Exception
        return None, "Could not find a match in the second pcap for mptcpstream %d" % df1_mptcpstream

    if len(mappings) <= 0:
        return None, "Could not find a match in the second pcap for tcpstream %d" % df1_mptcpstream

    print("len(df1)=", len(df1), " len(rawdf2)=", len(df2))
    mapped_connection = mappings[0].mapped
    print("Found mappings %s" % mappings)
    for mapping in mappings:
        print("Con: %s" % (mapping.mapped))

    return merge_mptcp_dataframes_known_streams(
        (df1, main_connection),
        (df2, mapped_connection)
    ), None


def merge_mptcp_dataframes_known_streams(
    con1: Tuple[pd.DataFrame, MpTcpConnection],
    con2: Tuple[pd.DataFrame, MpTcpConnection]
) -> pd.DataFrame:
    """
    Useful for reinjections etc...

    See
        merge_mptcp_dataframes

    Returns:
        Per-subflow dataframes

    """
    df1, main_connection  = con1
    df2, mapped_connection = con2

    log.info("Merging %s with %s" % (main_connection, mapped_connection,))

    mapping = map_mptcp_connection_from_known_streams(main_connection, mapped_connection)

    # log.info("Mapping %r" % (mapping,))

    # TODO when looking into the cache, check for mptcpstream
    # prepare metadata
    # we should write mptcpdest before the column names change
    # finally we set the mptcp destination to help with further processing
    # for sf in main_connection.subflows:
    # add suffix ?

    # print("df1 %d" % len(df1))
    # print(df1[['ipsrc', 'sport', 'tcpstream', 'mptcpstream']])

    # print("df1 packets for mptcpstream 0: %d" % len(df1[df1.mptcpstream == 0 ]))

    # TODO test
    # CategoricalDtype(categories=['b', 'a'], ordered=True)
    df1['mptcpdest'] = pd.Series(np.nan, dtype=dtype_role)
    for destination in ConnectionRoles:
        # TODO 
        # print("Selecting destination %s" % destination)
        q = main_connection.generate_direction_query(destination)
        # q = "(mptcpstream==0 and (tcpstream==0  and ipsrc=='10.0.0.1' and sport==(59482) ))"
        # print("with query %s" % q )
        df = df1.query(q).index
        df1.loc[df, 'mptcpdest' ] = destination
        # print("SELECTED %d for direction %s" % (len(df), destination))
        # print(df)
        # df["mptcpdest"] = destination
        # print(df[TCP_DEBUG_FIELDS].head(20))
        # print(df1[MPTCP_DEBUG_FIELDS + ['ipsrc', 'ipdst'] ].head())

    # print(df1[MPTCP_DEBUG_FIELDS].head())
    # import sys
    # sys.exit(1)

    # /home/teto/mptcpanalyzer/mptcpanalyzer/data.py:580: SettingWithCopyWarning: 
    # A value is trying to be set on a copy of a slice from a DataFrame.
    # Try using .loc[row_indexer,col_indexer] = value instead

            # raise Exception("TODO")

    # todo should be inplace
    df_total = None  # type: pd.DataFrame
    # print("TCP mapping" % TcpMapping)
    for sf, mapped_sf in mapping.subflow_mappings:

        # print("%r mapped to %r" % (sf, mapped_sf))
        # print("test %r" % (mapped_sf.mapped))
        df_temp = merge_tcp_dataframes_known_streams(
            (df1, sf),
            (df2, mapped_sf.mapped)
        )


        df_total = pd.concat([df_temp, df_total])

    # we do it a posteriori so that we can still debug a dataframe with full info
    # print(df_total.columns)
    # cols2drop = [ 'tcpflags']
    # cols2drop = _receiver(cols2drop)
    # df_total.drop(labels=cols2drop)

    log.info("Merging %s with %s" % (main_connection, mapped_connection,))
    # TODO I need to return sthg
    return df_total



def generate_tcp_directional_owd_df(
    sender_df, receiver_df,
    dest,
    **kwargs
):
    """
    Generate owd in one sense
    sender_df and receiver_df must be perfectly cleaned beforehand

    Attr:

    Returns
    """

    mapped_df = map_tcp_packets(sender_df, receiver_df)

    # on sender_id = receiver_mapped_packetid

    # this is the stochastic part
    # print("== DEBUG START ===")
    # print("Mapped index:")
    # print(mapped_df[["rcv_pktid", "packetid"]].head())
    # # print(mapped_df[["abstime", "tcpseq", "sendkey"]].head())
    # # print(mapped_df[["abstime", "tcpseq", "sendkey"]].head())
    # print("== DEBUG END ===")
    # print("Mapped df:")
    # print(mapped_df)
    # print("receiver df:")
    # print(receiver_df)
    # if mapped_df.rcv_pktid.is_unique is False:
    #     log.warn("There seems to be an error: some packets were mapped several times.")
    # # check for nan/ drop them
    # if mapped_df.rcv_pktid.is_unique is False:
    #     log.warn("There seems to be an error: some packets were mapped several times.")
    # res = pd.merge(
    #     mapped_df, receiver_df,
    #     left_on="rcv_pktid",
    #     right_on="packetid",
    #     # right_index=True,
    #     # TODO en fait suffit d'inverser les suffixes, h1, h2
    #     suffixes=suffixes, # how to suffix columns (sender/receiver)
    #     how="inner", #
    #     indicator=True # adds a "_merge" suffix
    # )
    # newcols = {
    #     'score' + suffixes[0]: 'score',
    # }
    # res.rename(columns=newcols, inplace=True)

    res = mapped_df
    res['owd'] = res['abstime' + RECEIVER_SUFFIX] - res['abstime' + SENDER_SUFFIX]

    # print("unidirectional results\n", res[["owd"]].head())
    return res



def map_tcp_packet(df, packet, explain=False) -> List[Tuple[Any, float]]:
    # instead should be index ?
    """
    Packets may disappear, get retransmitted

    Args:
        packet:

    Returns:
        a list of tuples (pktid, score)
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
        # else:
        #     log.debug("Found no match for pktid %d, skipping.." % _get_pktid(packet))

    # sort by score
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores


def print_weird_owds(df):
    """
    Checks for negative owds
    """
    negative_owds = df[df.owd < 0]
    print("Listing")
    for row in negative_owds.itertuples():
        # print(*row)
        print("""row sender pktid={packetid_sender}/abstime={abstime_sender}
                pktid={packetid_receiver}/abstime={abstime_receiver} owd={owd}"""
                .format( **row._asdict()))


def map_tcp_packets(
    sender_df, receiver_df,
    explain=[],
    mode="hash"
        # con1: TcpConnection, con2: TcpConnection
) -> pd.DataFrame:
    if mode == "hash":
        res = map_tcp_packets_via_hash(sender_df, receiver_df, explain)
    else:
        res = map_tcp_packets_score_based(sender_df, receiver_df, explain)

    log.info("Merged packets. Resulting dataframe of size {} generated from {} and {}".format(
        len(res), len(sender_df), len(receiver_df)
    ))
    log.info("{} unmapped packets. ".format(
        len(res[res._merge == "left_only"]) + len(res[res._merge == "right_only"])
    ))

    def _show_unmapped_pkts():
        print(res[res._merge == "left_only"])
        print(res[res._merge == "right_only"])

    _show_unmapped_pkts()

    return res



def map_tcp_packets_via_hash(
    sender_df, receiver_df, 
    *kargs,
    **kwargs
    ):
    """
    Merge on hash of different fields
    """
    log.info("Merging packets via hash")
    debug_cols = ["packetid", "hash", "reltime"]
    # TODO do a join
    # df_final = sender_df.assign(rcv_pktid=np.nan, score=np.nan,)
    # print("SENDER")
    # print(sender_df[debug_cols].head(5))
    # print("RECEIVER")
    # print(receiver_df[debug_cols].head(5))

    # todo we could now use merge_asof
    res = pd.merge(
        sender_df, receiver_df,
        on="hash",
        suffixes=(SENDER_SUFFIX, RECEIVER_SUFFIX), #  columns suffixes (sender/receiver)
        how="outer", # we want to keep packets from both
        # we want to know how many packets were not mapped correctly, adds the _merge column
        # can take values "left_only"/ "right_only" or both
        indicator=True ,
        validate="one_to_one",
    )

    #print("hash-based Map")
    ## print(sender_df[['hash', 'packetid']].head(20))
    ## print(receiver_df[['hash', 'packetid']].head(20))
    ## 
    print(res.columns)
    #print(hashing_fields)
    #print(res[TCP_DEBUG_FIELDS].head(20))
    return res


def map_tcp_packets_score_based(
    sender_df, receiver_df,
    explain=[],
    mode="hash"
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

    # returns a new object with new columns rcv_pktid, score initialized to NaN
    df_final = sender_df.assign(rcv_pktid=np.nan, score=np.nan,)
    # print(sender_df)
    # log.debug(df_final.columns)

    # # Problem is to identify lost packets and retransmitted ones
    # # so that they map to the same or none ?
    limit = 5  # limit nb of scores to display

    # print(df_final)

    pkt_column = df_final.columns.get_loc('rcv_pktid')
    score_column = df_final.columns.get_loc('score')

    for row_id, row in enumerate(sender_df.itertuples(index=False)):

        explain_pkt = row.packetid in explain
        scores = map_tcp_packet(receiver_df, row, explain_pkt)
        # takes best score index
        # df_final.loc[row.index , 'mapped_index'] = 2 # scores[0][0]
        # print(type(row.Index), type(row.index))
        if len(scores) >= 1:
            print("first %d packets (pandas.index/score)s=\n%s" % (limit, scores[:limit]))
            if explain_pkt:
                for idx, score in scores:
                    log.debug("Score %s=%s" % (idx, score))
            idx, score = scores[0]

            # You should never modify something you are iterating over.
            # print("row.Index=%r (out of %d) and idx=%r" % (row.Index, len(df_final), idx))
            print("row.id=%r (out of %d) and idx=%r" % (row_id, len(df_final), idx))
            # print("df_final.=%r " % (row.Index, idx))
            # df_final.iat[row.Index, df_final.columns.get_loc('rcv_pktid')] = idx
            df_final.iloc[row_id, pkt_column] = idx
            # df_final.loc[row.Index, 'rcv_pktid'] = idx
            # df_final.at[row.Index, 'rcv_pktid'] = idx
            # iat only accepts an integer while iloc can accept a tuple etc
            # print(df_final.iat[row.Index].score)
            df_final.iloc[row_id, score_column] = score
            # TODO we might want to remove that packets from further search

        # drop the chosen index so that it doesn't get used a second time
        # todo pb la c qu'on utilise les packet id comme des index :/
            print("Score %f assigned to index %s" % (score, idx))
            # df2.drop(df2.index[[idx]], inplace=True)
            # df2.drop(idx, inplace=True)
        else:
            # log.debug("No map found for this packet")
            log.debug("Found no match for pktid %d, skipping.." % row.packetid)

        # print("registered = %s" % ( df_final.loc[row.Index, 'mapped_index'])) # , ' at index: ', row.index )

    # checks that
    # if df_final.rcv_pktid.is_unique is False:
    #     log.warn("There seems to be an error: some packets were mapped several times.")

    # print("head=\n", df_final.head())
    return df_final



# TODO return TcpMapping
# def sort_tcp_(rawdf: pd.DataFrame, main: TcpConnection) -> List[TcpMapping]:
def map_tcp_stream(rawdf: pd.DataFrame, main: TcpConnection) -> List[TcpMapping]:
    """
    Returns:
        a sorted list of mappings (tcpconnection, score) with the first one being the most probable
    """

    results = []
    for tcpstream in rawdf["tcpstream"].unique():
        other = TcpConnection.build_from_dataframe(rawdf, tcpstream)
        score = main.score(other)
        if score > float('-inf'):
            mapping = TcpMapping(other, score)
            results.append(mapping)

    # decreasing sort based on the score
    results.sort(key=lambda x: x[1], reverse=True)

    return results

def map_mptcp_connection_from_known_streams(
    # rawdf2: pd.DataFrame, 
    main: MpTcpConnection,
    other: MpTcpConnection
    ) -> MpTcpMapping:
    """
    Attempts to map subflows only if score is high enough
    """
    # other = MpTcpConnection.build_from_dataframe(rawdf2, mptcpstream2)
    def _map_subflows(main: MpTcpConnection, mapped: MpTcpConnection):
        """
        """
        mapped_subflows = []
        for sf in main.subflows():

            # generates a list (subflow, score)
            scores = list(map(lambda x: TcpMapping(x, sf.score(x)), mapped.subflows()))
            scores.sort(key=lambda x: x[1], reverse=True)
            # print("sorted scores when mapping %s:\n %r" % (sf, scores))
            mapped_subflows.append( (sf, scores[0]) )
            # TODO might want to remove the selected subflow from the pool of candidates
        
        return mapped_subflows

    mptcpscore = main.score(other)
    mapped_subflows = None
    if mptcpscore > float('-inf'):
        # (other, score)
        mapped_subflows = _map_subflows(main, other)

    mapping = MpTcpMapping(mapped=other, score=mptcpscore, subflow_mappings=mapped_subflows)
    # print("mptcp mapping %s" % (mapping,))
    return mapping


def map_mptcp_connection(
    rawdf2: pd.DataFrame, main: MpTcpConnection
    ) -> List[MpTcpMapping]:
# List[Tuple[MpTcpConnection, float]]:
    """
    warn: Do not trust the results yet WIP !

    Returns:
        List of (connection, score) with the best mapping first

    This function tries to map a mptcp.stream from a dataframe (aka pcap) to mptcp.stream
    in another dataframe. For now it just looks at IP level stuff without considering subflow 
    mapping score
    """
    log.warning("mapping between datasets is not considered trustable yet")
    results = []  # type: List[MpTcpMapping]

    # mappings = {}  # type: Dict[int,Tuple[Any, float]]

    score = -1  # type: float
    results = []


    # print("%r" % main)
    # print(rawdf2["mptcpstream"].unique().dropna())

    for mptcpstream2 in rawdf2["mptcpstream"].dropna().unique():
        other = MpTcpConnection.build_from_dataframe(rawdf2, mptcpstream2)
        mapping = map_mptcp_connection_from_known_streams(main, other)
        # score = main.score(other)
        # if score > float('-inf'):
        #     # (other, score)
        #     mapped_subflows = _map_subflows(main, other)
        #     mapping = MpTcpMapping(mapped=other, score=score, subflow_mappings=mapped_subflows)
        results.append(mapping)

    # sort based on the score
    results.sort(key=lambda x: x[1], reverse=True)

    return results


def classify_reinjections(df_all: pd.DataFrame) -> pd.DataFrame:
    """
    here the idea is to look at reinjections on the receiver side, see which one is first
    packets with reinjected_in_receiver are (at least they should) be the first DSN arrived.

    Returns
        a new dataframe with an added column "redundant"
    """

    df_all["redundant"] = False

    df = df_all[ df_all._merge == "both" ]
    

    # print(df_all[ pd.notnull(df_all[_sender("reinjection_of")])] [
    #     _sender(["reinjection_of", "reinjected_in", "packetid", "reltime"]) +
    #     _receiver(["packetid", "reltime"])
    # ])


    for destination in ConnectionRoles:

        sender_df = df[df.mptcpdest == destination]

        # print(sender_df[ sender_df.reinjected_in.notna() ][["packetid", "reinjected_in"]])
        # print("successful reinjections" % len(reinjected_in))

        # select only packets that have been reinjected

        # print("%d sender_df packets" % len(sender_df))
        # print(sender_df["reinjection_of"])
        reinjected_packets = sender_df.dropna(axis='index', subset=[ _sender("reinjection_of") ])

        # print("%d reinjected packets" % len(reinjected_packets))
        # with pd.option_context('display.max_rows', None, 'display.max_columns', 300):
        #     print(reinjected_packets[["packetid", "packetid_receiver", *_receiver(["reinjected_in", "reinjection_of"])]].head())


        for reinjection in reinjected_packets.itertuples():
            # here we look at all the reinjected packets

            # print("full reinjection %r" % (reinjection,))

            # if there are packets in _receiver(reinjected_in), it means the reinjections 
            # arrived before other similar segments and thus these segments are useless
            # it should work because 
            # useless_reinjections = getattr(reinjection, _receiver("reinjected_in"), [])

            # if it was correctly mapped
            # TODO why reinjection._merge doesn't exist ?
            if reinjection._1 != "both":
                # TODO count missed classifications ?
                log.debug("reinjection %d could not be mapped, giving up..." % (reinjection.packetid))
                continue

            initial_packetid = reinjection.reinjection_of[0]
            # print("initial_packetid = %r %s" % (initial_packetid, type(initial_packetid)))

            # 
            original_packet = df_all.loc[ df_all.packetid == initial_packetid ].iloc[0]

            if original_packet._merge != "both":
                # TODO count missed classifications ?
                log.debug("Original packet %d could not be mapped, giving up..." % (original_packet.packetid))
                continue


            orig_arrival  = getattr(original_packet, _receiver("reltime"))
            reinj_arrival = getattr(reinjection, _receiver("reltime"))


            if orig_arrival < reinj_arrival:
                # print("GOT A MATCH")
                df_all.loc[ df_all[ _sender("packetid")] == reinjection.packetid, "redundant"] = True

    return df_all
