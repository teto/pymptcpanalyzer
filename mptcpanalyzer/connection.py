import pandas as pd
import logging
from mptcpanalyzer import Destination, MpTcpException

from enum import Enum

log = logging.getLogger(__name__)


class Filetype(Enum):
    unsupported = 0
    pcap = 1
    sql = 2
    csv = 3


class MpTcpSubflow:
    def __init__(self,
   tcpstreamid,
   clientip, serverip, cport, sport,
   addrid
            ):
        self.client_ip = clientip
        self.server_ip = serverip
        self.server_port = sport
        self.client_port = cport
        self.tcpstreamid = tcpstreamid
        """ Equivalent to wireshark tcp.stream"""

    @staticmethod
    def create_subflow(tcpid, ipsrc, ipdst, sport, dport, addrid, swap: bool=False):
        """
        Args:
            swap: Swap src and destination
        """
        if swap:
            return  MpTcpSubflow(tcpid, ipdst, ipsrc, dport, sport, addrid )
        return  MpTcpSubflow(tcpid, ipsrc, ipdst, sport, dport, addrid)

    def generate_direction_query(self, dest : Destination ):
        """
        """
        q = "tcpstream==%d " % self.tcpstreamid
        if dest == Destination.Both:
            return q

        if dest == Destination.Client:
            ipsrc = self.server_ip
            sport = self.server_port
        else:
            ipsrc = self.client_ip
            sport = self.client_port

        q += " and ipsrc=='%s' and sport==(%d) " % (ipsrc, sport)
        return q

    def __str__(self):
        line = ("tcp.stream {s.tcpstreamid} : {s.client_ip}:{s.client_port} "
                " <-> {s.server_ip}:{s.server_port} ").format( s=self,)
        return line


class MpTcpConnection:
    """
    Holds key characteristics of an MPTCP connection: keys, tokens, subflows

    This should be created via :member:`.build_from_dataframe`
    """
    def __init__(self, mptcpstreamid, client_key, client_token, server_key,
            server_token, subflows, **kwargs):

        self.mptcpstreamid = mptcpstreamid
        self._subflows = subflows
        self.client_key = client_key
        self.client_token = client_token
        self.server_key = server_key
        self.server_token = server_token



    def generate_direction_query(self, destination: Destination):
        """

        Returns
            Query
        """
        # TODO test this function

        queries = []
        # queries.append("mptcpstream == %d" % self.mptcpstreamid)
        for sf in self.subflows:
            q = " (" + sf.generate_direction_query(destination) + ") "
            print(q)
            queries.append(q)
        result =  "(mptcpstream==%d and (%s))" % (self.mptcpstreamid, " or ".join(queries))
        
        print(result)
        return result

    @property
    def subflows(self):
        return self._subflows

    @staticmethod
    def build_from_dataframe(ds: pd.DataFrame, mptcpstreamid: int):
        """
        Instantiates a class that describes an MPTCP connection
        """


        def get_index_of_non_null_values(serie):
            # http://stackoverflow.com/questions/14016247/python-find-integer-index-of-rows-with-nan-in-pandas/14033137#14033137
            # pd.np.nan == pd.np.nan retursn false in panda so one should use notnull(), isnull()
            return serie.notnull().nonzero()[0]


        ds = ds[ds.mptcpstream == mptcpstreamid]
        if len(ds.index) == 0:
            raise MpTcpException("No packet with this stream id")

        # this returns the indexes where a sendkey is set :
        res = get_index_of_non_null_values(ds["sendkey" ])
        if len(res) < 2:
            raise MpTcpException("Could not find the initial keys")

        cid = res[0]
        client_key = ds["sendkey"].iloc[ cid ]
        client_token = ds["expected_token"].iloc[ cid ]
        server_key = ds["sendkey"].iloc[ res[1] ]
        server_token = ds["expected_token"].iloc[ res[1] ]
        # print("client key", client_key, "/", client_token, "/", server_key, server_token)
        master_id = ds["tcpstream"].iloc[0]

        subflows = []
        master_sf = MpTcpSubflow.create_subflow (
                master_id, ds['ipsrc'].iloc[ cid ], ds['ipdst'].iloc[ cid ],
                ds['sport'].iloc[ cid ], ds['dport'].iloc[ cid ],
                "master", swap=False)

        subflows.append(master_sf)
        tcpstreams = ds.groupby('tcpstream')
        for tcpstreamid, subflow_ds in tcpstreams:
            if tcpstreamid == master_id:
                continue
            res = get_index_of_non_null_values(subflow_ds["recvtok"])
            if len(res) < 1:
                raise MpTcpException("Missing MP_JOIN")
            row = res[0]
            token = subflow_ds["recvtok"].iloc[ row ]
            subflow = MpTcpSubflow.create_subflow (tcpstreamid, subflow_ds['ipsrc'].iloc[ row ], subflow_ds['ipdst'].iloc[ row ],
                subflow_ds['sport'].iloc[ row ], subflow_ds['dport'].iloc[ row ],
                addrid=None, swap = (token == client_token) )
            subflows.append(subflow)

        result =  MpTcpConnection(mptcpstreamid, client_key, client_token,
                server_key, server_token,
                subflows)
        log.debug("Creating connection %s", result)
        return result


    @staticmethod
    def filter_ds(data, **kwargs):
        """
        Filters a pandas dataset
        :param data: a Pandas dataset
        :param kwargs: Accepted keywords are

        direction = client or server
        """
        dat = data
        for field, value in dict(**kwargs).items():
            # print("name, value", field)
            query = "{field} == '{value}'".format(field=field, value=value)

            log.debug("Running query %s" % query)
            dat = data.query(query)
        return dat


    def compute_subflows(self):
        """
        """
        # tcpstreams = self.ds.groupby('tcpstream')
        pass

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        res = """
        Server key/token: {skey}/{stoken}
        Client key/token: {ckey}/{ctoken}
        """.format(
                skey=self.server_key,
                stoken=self.server_token,
                ckey=self.client_key,
                ctoken=self.client_token,
                )
                # extra = ""
                # addrid = []
                # if len(gr2[gr2.master == 1]) > 0:
                #     addrid = ["master", "master"]
                # else:
                #     # look for MP_JOIN <=> tcp.options.mptcp.subtype == 1
                #     # la ca foire
                #     for i, ipsrc in enumerate( [gr2['ipsrc'].iloc[0], gr2['ipdst'].iloc[0] ]):
                #         gro=gr2[(gr2.tcpflags >= 2) & (gr2.addrid) & (gr2.ipsrc == ipsrc)]
                #         # print("nb of results:", len(gro))
                #         if len(gro):
                #             # print("i=",i)
                #             value = int(gro["addrid"].iloc[0])
                #         else:
                #             value = "Unknown"
                #         addrid.insert(i, value)

        return res
