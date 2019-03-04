import pandas as pd
import logging
import math
import numpy as np
from mptcpanalyzer import ConnectionRoles, MpTcpException, TcpStreamId, MpTcpStreamId, TcpFlags
import mptcpanalyzer as mp
from typing import List, NamedTuple, Tuple, Dict, Union
from enum import Enum
from dataclasses import dataclass

log = logging.getLogger(__name__)


def swap_role(role : ConnectionRoles):
    """while waiting to get next to work with enum"""
    if role == ConnectionRoles.Server:
        return ConnectionRoles.Client
    else:
        return ConnectionRoles.Server


class Filetype(Enum):
    unsupported = 0
    pcap = 1
    sql = 2
    csv = 3

@dataclass
class TcpConnection:
    """
    Everything capable of identifying a connection

    Note:
        There exists in ipaddress module

    Attributes:
        tcpstreamid: wireshark tcp.stream
    """

    tcpstreamid: TcpStreamId
    tcpclient_ip: str
    tcpserver_ip: str
    server_port: int
    client_port: int
    isn: int = None


    def generate_direction_query(self, tcpdest: ConnectionRoles) -> str:
        """
        Filter packets according to the tcp notion of client/server destination
        """
        q = "tcpstream==%d " % self.tcpstreamid
        if tcpdest is None:
            return q

        if tcpdest == ConnectionRoles.Client:
            ipsrc = self.tcpserver_ip
            server_port = self.server_port
        else:
            ipsrc = self.tcpclient_ip
            server_port = self.client_port

        # server_port used to be
        q += " and ipsrc=='%s' and sport==%d " % (ipsrc, server_port)
        return q

    def sort_candidates(self, ):
        """
        Sort a list
        """
        pass

    def format_mapping(self, mapping: 'TcpMapping', verbose=False):
        # res = "tcp stream {c1.tcpstreamid} <-> {c2.tcpstreamid} with score={score}".format(
        res = "{c1} mapped to {c2} with score={score}".format(
                c1=self, c2=mapping[0], score=mapping[1])

        # print(res)
        return res

    def score(self, other: 'TcpConnection'):
        """
        If every parameter is equal, returns +oo else 0
        TODO also match on isn in case ports got reused
        """
        score = 0
        if (self.tcpserver_ip == other.tcpserver_ip and
                self.tcpclient_ip == other.tcpclient_ip and
                self.client_port == other.client_port and
                self.server_port == other.server_port):
                return float('inf')

        score += 10  if self.tcpserver_ip == other.tcpserver_ip else 0
        score += 10  if self.tcpclient_ip == other.tcpclient_ip else 0
        score += 10  if self.client_port == other.client_port else 0
        score += 10  if self.server_port == other.server_port else 0

        # TODO more granular score
        return score


    def fill_dest(self, df) -> pd.DataFrame:

        for dest in ConnectionRoles:

            log.debug("Looking at destination %s" % dest)
            q = self.generate_direction_query(dest)
            df_dest = df.query(q, engine="python")
            print("tcpdest %r" % dest)
            df.loc[df_dest.index, 'tcpdest'] = dest

        # print(df.tcpdest.head())
        # assert df['tcpdest'].notnull() == , "every packet should have tcpdest set"
        return df


    def __eq__(self, other):
        """
        Ignores
        A NAT/PAT could have rewritten IPs in which case you probably
        should add another function like score
        Should implement __neq__ ?
        """
        # print("self=%r"% self)
        # print("other=%r"% other)
        if type(other) is type(self):
            return self.score(other) == float('inf')
        return False

    @staticmethod
    def build_from_dataframe(rawdf: pd.DataFrame, tcpstreamid: TcpStreamId) -> 'TcpConnection':
        """
        Instantiates a class that describes an MPTCP connection

        Look for syn and synack => don't assume packets in order

        TODO: might need to pass a name changer
        """

        df = rawdf[rawdf.tcpstream == tcpstreamid]
        if len(df.index) < 1:
            raise MpTcpException("No packet with this tcp.stream id %r" % tcpstreamid)

        # + mp.TcpFlags TODO record ISN !!
        # syns = df[df.tcpflags == mp.TcpFlags.SYN]
        # if len(syns) == 0
        #     raise MpTcpException("No packet with this stream id")

        # returns a  serie
        syns = np.bitwise_and(df['tcpflags'], TcpFlags.SYN)
        # TODO check times
        # syn_df = ds.where(ds.tcpflags == syn_only)
        # synack_df = ds.where(ds.tcpflags == synack_val)

        if len(syns.index) < 1:
            raise MpTcpException("No packet with any SYN flag for tcpstream %d" % tcpstreamid)

        idx = syns.index[0]
        row = df.loc[idx,]

        result = TcpConnection(
            TcpStreamId(tcpstreamid),
            row['ipsrc'],
            row['ipdst'],
            client_port=row['sport'],
            server_port=row['dport']
        )

        if df.loc[idx, "tcpflags"] & TcpFlags.ACK:
            # then revert the flow
            log.debug("We have seen the syn/ack instead of syn, invert destination")
            result = result.reversed()

        log.debug("Created connection %s" % result)
        return result

    def reversed(self):
        # doesn't make sense really ?
        return TcpConnection(
            self.tcpstreamid, self.tcpserver_ip, self.tcpclient_ip,
            self.server_port, self.client_port,
        )

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        # :>5d
        # TODO should be converted to int instead, would spare some memory
        line = ("tcp.stream {s.tcpstreamid:.0f}: {s.tcpclient_ip}:{s.client_port:0>5.0f} "
                " -> {s.tcpserver_ip}:{s.server_port:0>5.0f} ").format(s=self,
                        # tcpstreamid=self.tcpstreamid
                        )
        return line


# should it ?
@dataclass
class MpTcpSubflow(TcpConnection):
    """

    """

    """ to which mptcp side belongs the tcp server"""
    mptcpdest: ConnectionRoles = None
    addrid: int = None

    # def __init__(self, mptcpdest: ConnectionRoles, addrid=None, **kwargs) -> None:
    #     super().__init__(**kwargs)
    #     self.addrid = addrid
    #     # self.rcv_token = rcv_token
    #     # token_owner ?
    #     """ to which mptcp side belongs the tcp server"""
    #     self.mptcpdest = mptcpdest

    @staticmethod
    def create_subflow(**kwargs):
        """
        Args:
        """
        sf = MpTcpSubflow(**kwargs)
        return sf

    def reversed(self):
        res = self.create_subflow(
            mptcpdest=swap_role(self.mptcpdest),
            tcpstreamid=self.tcpstreamid,
            tcpclient_ip=self.tcpserver_ip,
            tcpserver_ip=self.tcpclient_ip,
            client_port=self.server_port,
            server_port=self.client_port,
        )
        log.warn("Losing addrid")
        # we lose the addrid in opposite direction
        # res.addrid = self.addrid
        # raise Exception("check for rcv_token")
        return res

    def mptcp_dest_from_tcpdest(self, tcpdest: ConnectionRoles):
        return self.mptcpdest if tcpdest == ConnectionRoles.Server else swap_role(self.mptcpdest)

    def generate_mptcp_direction_query(self, mptcpdest: ConnectionRoles):
        """
        Filter packets according to their MPTCP destination
        """
        # for now we assume that TcpConnection are always created with the Server
        # as destination
        tcpdest = ConnectionRoles.Server
        if self.mptcpdest != mptcpdest:
            # t = self.reversed()
            tcpdest = swap_role(tcpdest)

        return super(MpTcpSubflow, self).generate_direction_query(tcpdest)

    def __str__(self):
        """ Plot destination on top of it """
        res = super().__str__()
        res += " (mptcpdest: %s)" % self.mptcpdest
        return res
            #
            # return super(TcpConnection).generate_direction_query()
        # if dest == ConnectionRoles.Client:
        #     ipsrc = self.tcpserver_ip
        #     server_port = self.server_port
        # else:
        #     ipsrc = self.tcpclient_ip
        #     server_port = self.client_port

        # q += " and ipsrc=='%s' and server_port==(%d) " % (ipsrc, server_port)
        # return q



# TODO provide as a dataclass
# @dataclass
class MpTcpConnection:
    """
    Holds key characteristics of an MPTCP connection: keys, tokens, subflows

    This should be created via :member:`.build_from_dataframe`

    subflows can be any order
    """
    # mptcpstreamid: MpTcpStreamId

    def __init__(self,
            mptcpstreamid: int,
            client_key: int, client_token: int, server_key: int,
            server_token, subflows, **kwargs) -> None:
        """
        """
        self.mptcpstreamid = mptcpstreamid
        self._subflows = subflows
        self.keys = {
            ConnectionRoles.Client: client_key,
            ConnectionRoles.Server: server_key,
        }

        self.tokens = {
            ConnectionRoles.Client: client_token,
            ConnectionRoles.Server: server_token,
        }

    def __contains__(self, key: MpTcpSubflow):
        """
        Mostly an approximation
        """
        return key in self.subflows() or key.reversed() in self.subflows()

    def generate_direction_query(self, mptcpdest: ConnectionRoles) -> str:
        """
        Filter packets according to the mptcp notion of client/server mptcpdest
        this is a bit different of TcpConnection.generate_direction_query and means that
        some subflows

        Returns
            Query
        """
        queries = []
        for sf in self.subflows():

            q = " (" + sf.generate_mptcp_direction_query(mptcpdest) + ") "
            queries.append(q)
        result =  "(mptcpstream==%d and (%s))" % (self.mptcpstreamid, " or ".join(queries))

        # print(result)
        return result


    # never used ?
    def fill_dest(self, df) -> pd.DataFrame:
        '''
        TODO it should set it also for subflows as well
        '''

        for dest in ConnectionRoles:

            log.log(mp.TRACE, "Looking at mptcp destination %s" % dest)
            q = self.generate_direction_query(dest)
            df_dest = df.query(q, engine="python")
            # print("mptcpdest %r" % dest)
            df.loc[df_dest.index, 'mptcpdest'] = dest

        for sf in self.subflows():
            sf.fill_dest(df)

        return df

    # @property
    def subflows(self, mptcpdest: ConnectionRoles = ConnectionRoles.Server):
        # TODO add a destination ?
        # assert 0
        return self._subflows

    @staticmethod
    def build_from_dataframe(ds: pd.DataFrame, mptcpstreamid: MpTcpStreamId) -> 'MpTcpConnection':
        """
        Instantiates a class that describes an MPTCP connection

        Look for the first 2 packets containing "sendkey"
        """

        ds = ds[ds.mptcpstream == mptcpstreamid]
        if len(ds.index) == 0:
            raise MpTcpException("No packet with this mptcp.stream id %r" % mptcpstreamid)

        syn_mpcapable_df = ds.where(ds.tcpflags == TcpFlags.SYN).dropna(subset=['sendkey'])
        synack_mpcapable_df = ds.where(ds.tcpflags == (TcpFlags.SYN | TcpFlags.ACK)).dropna(subset=['sendkey'])

        # print(syn_mpcapable_df[ ["sendkey", "tcpflags", "expected_token", "ipsrc"]])
        # print(synack_mpcapable_df[ ["sendkey", "tcpflags", "expected_token", "ipsrc"]])


        if len(syn_mpcapable_df) < 1:
            raise MpTcpException("Could not find the client MPTCP key")

        if len(synack_mpcapable_df) < 1:
            raise MpTcpException("Could not find the server MPTCP key")


        # not really rows but index
        client_id       = syn_mpcapable_df.index[0]
        server_id       = synack_mpcapable_df.index[0]
        client_key       = ds.loc[client_id, "sendkey"]
        client_token     = ds.loc[client_id, "expected_token"]
        server_key       = ds.loc[server_id, "sendkey"]
        server_token     = ds.loc[server_id, "expected_token"]
        master_tcpstream = ds.loc[client_id, "tcpstream"]

        # TODO now add a check on abstime
        if ds.loc[server_id, "abstime"] < ds.loc[client_id, "abstime"]:
            log.error("Clocks are not synchronized correctly")
            # print("")

        # print("line with key:")
        # print("client key = %r" % client_key)
        # print("server key = %r" % server_key)
        # print(ds.iloc[res[1], ])
        log.debug("Server token = %r" % server_token)
        assert math.isfinite(int(server_token))
        # assert math.isnan(server_token) == False

        subflows : List[MpTcpSubflow] = []

        # we assume this is the first seen sendkey, thus it was sent to the mptcp server
        master_sf = MpTcpSubflow.create_subflow(
            mptcpdest        = ConnectionRoles.Server,
            tcpstreamid      = master_tcpstream,
            tcpclient_ip     = ds.loc[client_id, 'ipsrc'],
            tcpserver_ip     = ds.loc[client_id, 'ipdst'],
            client_port      = ds.loc[client_id, 'sport'],
            server_port      = ds.loc[client_id, 'dport'],
            addrid           = 0   # master subflow has implicit addrid 0
        )

        subflows.append(master_sf)
        for tcpstreamid, subflow_ds in ds.groupby('tcpstream'):
            log.debug("Building subflow from tcpstreamid %d" % tcpstreamid)
            if tcpstreamid == master_tcpstream:
                log.debug("skipping %d, master already registered" % tcpstreamid)
                continue

            syn_join_df = subflow_ds.where(ds.tcpflags == TcpFlags.SYN).dropna(subset=['recvtok'])

            if len(syn_join_df) < 1:
                raise MpTcpException("Missing TCP client MP_JOIN")

            # assuming first packet is the initial SYN
            syn_join_id = syn_join_df.index[0]
            receiver_token = subflow_ds.loc[syn_join_id, "recvtok"]

            assert math.isfinite(int(receiver_token))

            # if we see the token
            log.debug("receiver_token %r to compare with server_token %r" % (receiver_token, server_token))
            log.debug("Test %s" % (receiver_token == server_token))
            mptcpdest = ConnectionRoles.Server if receiver_token == server_token \
                    else ConnectionRoles.Client

            subflow = MpTcpSubflow.create_subflow(
                mptcpdest   = mptcpdest,
                tcpstreamid =tcpstreamid,
                tcpclient_ip=subflow_ds.loc[syn_join_id,'ipsrc'],
                tcpserver_ip=subflow_ds.loc[syn_join_id,'ipdst'],
                client_port =subflow_ds.loc[syn_join_id,'sport'],
                server_port =subflow_ds.loc[syn_join_id,'dport'],
                addrid      =None,
                # rcv_token   =receiver_token,
            )

            log.debug("Created subflow %s" % subflow)

            subflows.append(subflow)

        result = MpTcpConnection(
            mptcpstreamid, client_key, client_token,
            server_key,
            server_token,
            subflows
        )
        return result


    @staticmethod
    def filter_ds(data, **kwargs):
        """
        Args:
        Filters a pandas dataset
             data: a Pandas dataset

        direction = client or server
        """
        dat = data
        for field, value in dict(**kwargs).items():
            query = "{field} == '{value}'".format(field=field, value=value)

            log.debug("Running query %s" % query)
            dat = data.query(query, engine="python")
        return dat


    def __eq__(self, other):
        """
        Ignores
        A NAT/PAT could have rewritten IPs in which case you probably
        should add another function like score
        """
        # print("self=%r", self)
        return self.score(other) == float('inf')

    def score(self, other: 'MpTcpConnection') -> float:
        """
        ALREADY FILTERED dataframes

        Returns:
            a score
            - '-inf' means it's not possible those 2 matched
            - '+inf' means
        """

        score = 0
        if len(self.subflows()) != len(other.subflows()):
            log.debug("FISHY: Datasets contain a different number of subflows (d vs d)" % ())
            score -= 5

        common_sf = []

        if self.keys[ConnectionRoles.Server] == other.keys[ConnectionRoles.Server] and self.keys[ConnectionRoles.Client] == other.keys[ConnectionRoles.Client]:
            log.debug("matching keys => same")
            return float('inf')


        # TODO check there is at least the master
        # with nat, ips don't mean a thing ?
        for sf in self.subflows():
            if sf in other.subflows() or sf.reversed() in other.subflows():
                log.debug("Subflow %s in common" % sf)
                score += 10
                common_sf.append(sf)
            else:
                log.debug("subflows %s doesn't seem to exist in other " % (sf))

        # TODO compare start times supposing cloak are insync ?
        # print( " score of %r" % score)
        return score


    def __str__(self):
        return str(self.mptcpstreamid)

    def __repr__(self):
        res = """
    Server key/token: {skey:>64.0f}/{stoken}
    Client key/token: {ckey}/{ctoken}
    """.format(
            skey=self.keys[ConnectionRoles.Server],
            stoken=self.tokens[ConnectionRoles.Server],
            ckey=self.keys[ConnectionRoles.Client],
            ctoken=self.tokens[ConnectionRoles.Client],
        )

        res += '\n    '.join(map(str, self.subflows()))
        return res


# TODO replace with dataclass
TcpMapping = NamedTuple('TcpMapping', [('mapped', TcpConnection), ("score", float)])

MpTcpMapping = NamedTuple('MpTcpMapping', [('mapped', MpTcpConnection), ("score", float),
    # make it a dict rather
        ("subflow_mappings", List[Tuple[MpTcpSubflow,TcpMapping]])
    ])

# @dataclass
# class MpTcpMapping:
#     mapped: MpTcpConnection
#     score: float
#     subflow_mappings: List[Tuple[MpTcpSubflow,TcpMapping]]


# @dataclass
# class TcpMapping:
#     mapped: TcpConnection
#     score: float


# MpTcpSubflowMapping = NamedTuple('TcpMapping', [('mapped', TcpConnection), ("score", float)])

