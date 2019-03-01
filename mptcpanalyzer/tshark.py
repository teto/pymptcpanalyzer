import logging
import subprocess
import os
import pandas as pd
import tempfile
import numpy as np
import shlex
import ast
from collections import namedtuple
from typing import List, Dict, Union, Optional, Callable, Any
from enum import Enum
# from mptcpanalyzer import Logger
import mptcpanalyzer as mp
import functools

logger = logging.getLogger(__name__)

# def _load_list(x, field="pass a field to debug"):
#     """
#     Loads x of the form "1,2,5" or None
#     for instance functools.partial(_convert_to_list, field="reinjectionOf"),
#     returns np.nan instead of [] to allow for faster filtering
#     """
#     # pandas error message are not the best to understand why the convert failed
#     # so we use this instead of lambda for debug reasons
#     print("converting field %s with value %r" % (field, x))
#     res = list(map(int, x.split(','))) if (x is not None and x != '') else np.nan
#     return res


# doesn't seem to work
# sometimes it will create a tuple only if there are several elements
def _load_list(x, field="set field to debug"):
    """
    Contrary to _convert_to_list
    """
    # logger.log(mp.TRACE, "Load field %s list %r" % (field, x))
    if x is None or len(x) == 0:
        return np.nan

    if x[0] != "[":
        x = "[" + x + "]"
    #if (x is not None and x != '') else np.nan
    res = ast.literal_eval(x)

    return res

class Filetype(Enum):
    unsupported = 0
    pcap = 1
    sql = 2
    csv = 3

def find_type(filename):
    """
    return a Filetype instance
    Naive implementation relying on filename. Expects only one dot in filename
    Assumes
    """
    filename, ext = os.path.splitext(os.path.basename(filename))
    if ext == ".csv":
        return Filetype.csv
    elif ext in (".pcap", ".pcapng"):
        return Filetype.pcap
    elif ext == ".sql":
        return Filetype.sql
    else:
        return Filetype.unsupported


"""
fullname: wireshark name
name: shortname used in mptcpanalyzer
type: python type pandas should convert this field to be careful that pandas integers
can't be NA, which is why we use floats mot of the time, which is a waste.
label: used when plotting

when a converter is specified, dtype will be set to object or str

hash: take this hash into account ?
"""
Field = namedtuple('Field', ['fullname', 'type', 'label', 'hash', 'converter'])

def _convert_flags(x):
    """ double int in case we deal with a float"""
    return int(x, 16)

def _convert_timestamp(x):
    # pd.Timestamp(ts_input=1529916720, unit="s", )
    return pd.to_datetime(x, unit="s", utc=True)
    # seconds=int(x)
    # return pd.Timestamp(ts_input=seconds, unit="s", nanosecond=x-seconds)


class TsharkConfig:
    """
    TODO
    in fact we could convert towards all formats supported by pandas:
    http://pandas.pydata.org/pandas-docs/stable/api.html#id12

    if you plan to add several options, you should use a specific profile instead,
    these options are meant to override a base profile
    """

    def __init__(self, delimiter="|", profile=None):
        """
        Args:
            profile: wireshark profiles will setup everything as it should
                except the gui column format that will be overriden to ensure
                compatibility with dissection system

             "tshark -G column-formats" list available formats
             name is then considered as a field accessible via  -e _ws.col.<name>
             %Cus => Custom
             see epan/column.c / col_set_rel_time
        """
        self.tshark_bin = "tshark"
        self.delimiter = delimiter
        self.profile = profile
        # ICMP packets can be pretty confusing as they will
        self._read_filter = "mptcp or tcp and not icmp"
        self.options = {
            # run tshark -G column-formats %At
            # %Cus:frame.time
            "gui.column.format": '"Time","%At","ipsrc","%s","ipdst","%d"',
            # "tcp.relative_sequence_numbers": True if tcp_relative_seq else False,
            "tcp.analyze_sequence_numbers": True,  # without it, the rest fails
            "mptcp.analyze_mappings": True,
            "mptcp.relative_sequence_numbers": True,
            "mptcp.intersubflows_retransmission": True,
            # Disable DSS checks which consume quite a lot
            "mptcp.analyze_mptcp": True,
        }
        self._tshark_fields = {}  # type: Dict[str, Field]

        # the split between option is to potentially allow for tcp-only wireshark inspection
        # (much faster)
        self.add_basic_fields()
        self.add_mptcp_fields()

    @property
    def read_filter(self, ):
        return self._read_filter

    def check_fields(self, fields: List[str]):
        """
        Check that this version of wireshark knows the fields we are going to use.
        It is helpful when working with a custom wireshark.
        """
        searches = fields
        cmd = [self.tshark_bin, "-G", "fields" ]

        logger.info("Checking for fields %s" % (cmd))
        with subprocess.Popen(cmd, stdout=subprocess.PIPE,
            universal_newlines=True, # opens in text mode
        ) as proc:
            matches: List[str] = []
            for line in proc.stdout:
                matches = [x for x in searches if x in line]
                searches = [item for item in searches if item not in matches]
            return matches


    def add_basic_fields(self):

        # when merging packets some packets are lost and thus have no packetid
        # so sadly we need a float64 in that case :'(
        self.add_field("frame.number", "packetid", 'UInt64', False, False)

        # TODO look at the doc ! with pd.Timestamp
        # dtype=pd.Int64Dtype()
        self.add_field("frame.time_relative", "reltime", np.float64, False, False)
        self.add_field("frame.time_epoch", "abstime", np.float64,
            "seconds+Nanoseconds time since epoch", None)
        self.add_field("_ws.col.ipsrc", "ipsrc", str, False, False)
        self.add_field("_ws.col.ipdst", "ipdst", str, False, False)
        self.add_field("ip.src_host", "ipsrc_host", str, False, False)
        self.add_field("ip.dst_host", "ipdst_host", str, False, False)
        self.add_field("tcp.stream", "tcpstream", 'UInt64', False, False)
        self.add_field("tcp.srcport", "sport", 'UInt16', False, False)
        self.add_field("tcp.dstport", "dport", 'UInt16', False, False)
        # rawvalue is tcp.window_size_value
        # tcp.window_size takes into account scaling factor !
        self.add_field("tcp.window_size", "rwnd", 'Int64', True, True)
        self.add_field("tcp.flags", "tcpflags", None, False, True, _convert_flags)
        # TODO set hash to true, isn't needed after tcpflags ?
        self.add_field("tcp.option_kind", "tcpoptions", None, False, False,
            functools.partial(_load_list, field="option_kind"), )
        self.add_field("tcp.seq", "tcpseq", 'UInt32', "TCP sequence number", True)
        self.add_field("tcp.len", "tcplen", 'UInt16', "TCP segment length", True)
        self.add_field("tcp.ack", "tcpack", 'UInt32', "TCP segment acknowledgment", True)
        self.add_field("tcp.options.timestamp.tsval", "tcptsval", 'Int64',
            "TCP timestamp tsval", True)
        self.add_field("tcp.options.timestamp.tsecr", "tcptsecr", 'Int64',
            "TCP timestamp tsecr", True)

    def add_mptcp_fields(self, advanced=True):
        # remove this one ?
        self.add_field("mptcp.expected_token", "expected_token", str, False, False)
        self.add_field("mptcp.stream", "mptcpstream", 'UInt64', False, False)
        
        # TODO convert to 'UInt64'
        self.add_field("tcp.options.mptcp.sendkey", "sendkey", str, False, True)
        self.add_field("tcp.options.mptcp.recvkey", "recvkey", str, False, True)
        self.add_field("tcp.options.mptcp.recvtok", "recvtok", str, False, True)

        self.add_field("tcp.options.mptcp.datafin.flag", "datafin", 'Int64', False, True)
        # this is a list really; can contain "2,4"
        self.add_field("tcp.options.mptcp.subtype", "subtype", str, False, True)
        self.add_field("tcp.options.mptcp.rawdataseqno", "dss_dsn", 'UInt64',
            "DSS Sequence Number", True)
        self.add_field("tcp.options.mptcp.rawdataack", "dss_rawack", 'UInt64',
            "DSS raw ack", True)
        self.add_field("tcp.options.mptcp.subflowseqno", "dss_ssn", 'UInt64',
            "DSS Subflow Sequence Number", True)
        self.add_field("tcp.options.mptcp.datalvllen", "dss_length", 'UInt64',
            "DSS length", True)
        self.add_field("tcp.options.mptcp.addrid", "addrid", None, False, True)
        self.add_field("mptcp.rawdsn64", "dsnraw64", np.float64, "Raw Data Sequence Number", False)
        self.add_field("mptcp.ack", "dack", 'UInt64', "MPTCP relative Ack", False)
        self.add_field("mptcp.dsn", "dsn", 'UInt64', "Data Sequence Number", False)

        if advanced:
            self.add_field("mptcp.related_mapping", "related_mappings", object, "DSS", False)
            # self.add_field("mptcp.duplicated_dsn", "reinjections", str, "Reinjections")
            # TODO use new names
            # it should be a list of integer
            self.add_field("mptcp.reinjection_of", "reinjection_of", object, "Reinjection", False,
                functools.partial(_load_list, field="reinjectedOfSender"),)
            self.add_field("mptcp.reinjected_in", "reinjected_in", object, "Reinjection list", False,
                functools.partial(_load_list, field="reinjectedInSender"), )


    def add_field(self, fullname: str, name: str, _type,
            label: Optional[str] = None,
            _hash: bool = False,
            converter: Optional[Callable] = None
        ):
        """
        It's kinda scary to use float everywhere but when using integers, pandas
        asserts at the first NaN
        It is also not possible to assign "int" for instance to subtype as there may be
        several subtypes in a packet (=> "2,4" which is not recognized as an int)

        Mapping between short names easy to use as a column title (in a CSV file)
        and the wireshark field name
        There are some specific fields that require to use -o instead,
        see tshark -G column-formats

        CAREFUL: when setting the type to int, pandas will throw an error if there
        are still NAs in the column. Relying on float64 permits to overcome this.

        .. note:

            tshark.exe -r file.pcap -T fields -E header=y -e frame.number -e col.AbsTime
                -e col.DeltaTime -e col.Source -e col.Destination -e col.Protocol
                -e col.Length -e col.Info

        """
        # TODO check for duplicates
        # TODO record as a dict instead
        if self._tshark_fields.get(name):
            raise Exception("Field %s already registered" % name)

        # converter = None
        # _type = type_or_converter
        # if inspect.isfunction(type_or_converter):
        #     converter = type_or_converter
        #     _type = None

        self._tshark_fields.setdefault(name,
            Field(fullname,  _type, label, _hash, converter))


    def export_to_csv(
        self, input_filename: str,
        output_csv, # a file descriptor
        fields_to_export: List[str],
    ):
        """
        output_csv can be an fd

        Returns exit code, stderr
        """
        logger.info("Converting pcap [{pcap}] ".format(pcap=input_filename,))

        if find_type(input_filename) != Filetype.pcap:
            raise Exception("Input filename not a capture file")

        cmd = self.generate_csv_command(
            # self.tshark_bin,
            fields_to_export,
            input_filename,
            # profile=self.profile,
            csv_delimiter=self.delimiter,
            options=self.options,
        )
        fd = output_csv
        # fd.write("# metadata: %s\n" % (cmd_str))
        fd.flush()  # need to flush else order gets messed up

        return self.run_tshark(cmd, fd)


    def filter_pcap(self, pcap_in, pcap_out):
        # cmd = [self.tshark_bin]
        cmd = [
            self.tshark_bin,
            "-r", pcap_in
        ]
        cmd.extend(["-2", '-R', self.read_filter])
        cmd.extend(['-w', pcap_out])

        return self.run_tshark(cmd, None)

    @staticmethod
    def run_tshark(cmd, stdout):
        cmd_str = ' '.join(shlex.quote(x) for x in cmd)
        logging.info(cmd_str)

        try:
            with subprocess.Popen(cmd, stdout=stdout, stderr=subprocess.PIPE) as proc:
                out, stderr = proc.communicate()
                stderr = stderr.decode("UTF-8")
                print("ran cmd", proc.args)
                print("stderr=", stderr)
                return proc.returncode, stderr

        except subprocess.CalledProcessError as e:
            logging.exception("An error happened while running tshark")
            print(e.cmd)
            return e.returncode, e.stderr

    @property
    def fields(self):
        return self._tshark_fields

    # def pseudocommand(self,):
    def __hash__(self,):
        """
        Used to generate hash
        """
        cmd = self.generate_csv_command(
            # self.tshark_bin,
            self._tshark_fields.keys(),
            "PLACEHOLDER",
            # profile=self.profile,
            csv_delimiter=self.delimiter,
            options=self.options,
            )
        # because lists are unhashable
        return hash(' '.join(cmd))

    # @staticmethod
    def generate_csv_command(
        self,
        fields_to_export: List[str],
        inputFilename,
        # profile=None,
        csv_delimiter='|',
        options={},
    ):
        """
        Generate tshark csv export command
        """

        # for some unknown reasons, -Y does not work so I use -2 -R instead
        # quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
        # single-quotes, n no quotes (the default).
        # the -2 is important, else some mptcp parameters are not exported
        cmd = [
            self.tshark_bin,
            "-E", "header=y",
            "-r", inputFilename,
            "-E", "separator=" + csv_delimiter,
        ]
        if self.profile:
            cmd.extend(['-C', self.profile])

        for option, value in options.items():
            cmd.extend(['-o', option + ":" + str(value)])

        if self.read_filter:
            cmd.extend(['-2', '-R', self.read_filter])

        cmd.extend(['-T', 'fields'])
        for f in fields_to_export:
            cmd.extend(['-e', f])
        return cmd
