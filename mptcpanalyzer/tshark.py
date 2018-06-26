import logging
import subprocess
import os
import tempfile
import numpy as np
from collections import namedtuple
from typing import List
from enum import Enum

log = logging.getLogger(__name__)


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
    print("Ext=", ext)
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
can't be NA, which is why we use floats mot of the time, which is a waste
label: used when plotting
"""
Field = namedtuple('Field', ['fullname', 'name', 'type', 'label', ])


class TsharkConfig:
    """
    TODO
    in fact we could convert towards all formats supported by pandas:
    http://pandas.pydata.org/pandas-docs/stable/api.html#id12

    if you plan to add several options, you should use a specific profile instead,
    these options are meant to override a base profile
    """

    def __init__(self, tshark_bin="tshark", delimiter="|", profile=None):
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
        self.tshark_bin = tshark_bin
        self.delimiter = delimiter
        self.profile = profile
        # ICMP packets can be pretty confusing as they will
        self.read_filter = "mptcp or tcp and not icmp"
        self.options = {
            "gui.column.format": '"Time","%Cus:frame.time","ipsrc","%s","ipdst","%d"',
            # "tcp.relative_sequence_numbers": True if tcp_relative_seq else False,
            "tcp.analyze_sequence_numbers": True,  # without it, the rest fails
            "mptcp.analyze_mappings": True,
            "mptcp.relative_sequence_numbers": True,
            "mptcp.intersubflows_retransmission": True,
            # Disable DSS checks which consume quite a lot
            "mptcp.analyze_mptcp": True,
        }
        self.fields = []  # type: List[Field]

        # the split between option is to potentially allow for tcp-only wireshark inspection
        # (much faster)
        self.add_basic_fields()
        self.add_mptcp_fields()
        try:
            matches = self.check_fields([ "mptcp.related_mapping" ])
        except subprocess.CalledProcessError as e:
            log.warn("Could not check fields ")
            pass

    def check_fields(self, fields: List[str]):
        """
        Check that this version of wireshark knows the fields we are going to use.
        It is helpful when working with a custom wireshark.
        """
        searches = fields
        cmd = [self.tshark_bin, "-G", "fields" ]

        log.info("Checking for fields %s" % (cmd))
        with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                universal_newlines=True, # opens in text mode
        ) as proc:
            matches: List[str] = [] 
            for line in proc.stdout:
                matches = [x for x in searches if x in line]
                searches = [item for item in searches if item not in matches]
            return matches


    def add_basic_fields(self):
        self.add_field("frame.number", "packetid", np.int64, False, )
        self.add_field("frame.time_relative", "reltime", None, False, )
        self.add_field("frame.time_delta", "time_delta", None, False, )
        self.add_field("frame.time_epoch", "abstime", None, False, )
        self.add_field("_ws.col.ipsrc", "ipsrc", str, False, )
        self.add_field("_ws.col.ipdst", "ipdst", str, False, )
        self.add_field("ip.src_host", "ipsrc_host", str, False)
        self.add_field("ip.dst_host", "ipdst_host", str, False)
        self.add_field("tcp.stream", "tcpstream", np.float64, False)
        self.add_field("tcp.srcport", "sport", np.float, False)
        self.add_field("tcp.dstport", "dport", np.float, False)
        # rawvalue is tcp.window_size_value
        # tcp.window_size takes into account scaling factor !
        self.add_field("tcp.window_size", "rwnd", np.float64, True)
        self.add_field("tcp.flags", "tcpflags", str, False)
        self.add_field("tcp.seq", "tcpseq", np.float64, "TCP sequence number")
        self.add_field("tcp.len", "tcplen", np.float64, "TCP segment length")
        self.add_field("tcp.ack", "tcpack", np.float64, "TCP segment acknowledgment")
        self.add_field("tcp.options.timestamp.tsval", "tcptsval", np.float64, "TCP timestamp tsval")
        self.add_field("tcp.options.timestamp.tsecr", "tcptsecr", np.float64, "TCP timestamp tsecr")

    def add_mptcp_fields(self, advanced=True):
        # remove this one ?
        self.add_field("mptcp.expected_token", "expected_token", str, False)
        self.add_field("mptcp.stream", "mptcpstream", np.float, False)
        self.add_field("tcp.options.mptcp.sendkey", "sendkey", np.float64, False)
        self.add_field("tcp.options.mptcp.recvkey", "recvkey", None, False)
        self.add_field("tcp.options.mptcp.recvtok", "recvtok", None, False)
        self.add_field("tcp.options.mptcp.datafin.flag", "datafin", np.float, False)
        self.add_field("tcp.options.mptcp.subtype", "subtype", str, False) # can contain "2,4"
        self.add_field("tcp.options.mptcp.rawdataseqno", "dss_dsn", np.float64, "DSS Sequence Number")
        self.add_field("tcp.options.mptcp.rawdataack", "dss_rawack", np.float64, "DSS raw ack")
        self.add_field("tcp.options.mptcp.subflowseqno", "dss_ssn", np.float64, "DSS Subflow Sequence Number")
        self.add_field("tcp.options.mptcp.datalvllen", "dss_length", np.float64, "DSS length")
        self.add_field("tcp.options.mptcp.addrid", "addrid", None, False)
        self.add_field("mptcp.rawdsn64", "dsnraw64", np.float64, "Raw Data Sequence Number")
        self.add_field("mptcp.ack", "dack", np.float64, "MPTCP relative Ack")
        self.add_field("mptcp.dsn", "dsn", np.float64, "Data Sequence Number")

        if advanced:
            self.add_field("mptcp.related_mapping", "related_mappings", None, "DSS")
            # self.add_field("mptcp.duplicated_dsn", "reinjections", str, "Reinjections")
            # TODO use new names
            # it should be a list of integer
            self.add_field("mptcp.reinjection", "reinjection_of", object, "Reinjection")
            self.add_field("mptcp.reinjection_listing", "reinjected_in", object, "Reinjection list")

    def add_field(self, fullname, name, type, label):
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

            tshark.exe -r file.pcap -T fields -E header=y -e frame.number -e col.AbsTime -e col.DeltaTime -e col.Source -e col.Destination -e col.Protocol -e col.Length -e col.Info

        """
        # TODO check for duplicates
        self.fields.append(
            Field(fullname, name, type, label)
        )

    def get_fields(self, field, field2=None):
        """
        TODO maybe we can use groupby instead
        Args:
            field: should be a string in Field
            field2: If field2 is None, returns a list with the field asked, else

        Returns:
            a dict( field values: field2 values)
        """
        l = self.fields
        keys = map(lambda x: getattr(x, field), l)
        if field2 is None:
            return keys

        return dict(zip(keys, map(lambda x: getattr(x, field2), l)))


    def export_to_csv(
        self, input_filename: str,
        output_csv, # a file descriptor
        fields_to_export: List[str],
    ):
        """
        output_csv can be an fd

        Returns exit code, stderr
        """
        log.info("Converting pcap [{pcap}] ".format(
            pcap=input_filename,
            )
        )

        if find_type(input_filename) != Filetype.pcap:
            raise Exception("Input filename not a capture file")

        cmd = self.generate_command(
            self.tshark_bin,
            fields_to_export,
            input_filename,
            self.read_filter,
            profile=self.profile,
            csv_delimiter=self.delimiter,
            options=self.options,
        )
        cmd_str = ' '.join(cmd)
        print(cmd_str)

        try:
            # TODO serialize wireshark options in header
            fd = output_csv
            fd.write("# metadata: %s\n" % (cmd_str))
            fd.flush()  # need to flush else order gets messed up
            with subprocess.Popen(cmd, stdout=fd, stderr=subprocess.PIPE) as proc:
                out, stderr = proc.communicate()
                stderr = stderr.decode("UTF-8")
                print("ran cmd", proc.args)
                print("stderr=", stderr)
                return proc.returncode, stderr

        except subprocess.CalledProcessError as e:
            log.error(str(e))
            print("ERROR")
            print(e.cmd)
            return e.returncode, e.stderr

    def hash(self,):
        cmd = self.generate_command(
            self.tshark_bin,
            self.get_fields('name'), # TODO convert to list
            "PLACEHOLDER",
            self.read_filter,
            profile=self.profile,
            csv_delimiter=self.delimiter,
            options=self.options,
            )
        # because lists are unhashable
        return hash(' '.join(cmd))

    @staticmethod
    def generate_command(
        tshark_exe,
        fields_to_export: List[str],
        inputFilename,
        read_filter=None,
        profile=None,
        csv_delimiter='|',
        options={},
    ):
        """
        Generate tshark command
        """

        # for some unknown reasons, -Y does not work so I use -2 -R instead
        # quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
        # single-quotes, n no quotes (the default).
        # the -2 is important, else some mptcp parameters are not exported
        cmd = [
            tshark_exe,
            "-E", "header=y", "-2",
            "-r", inputFilename,
            "-E", "separator=" + csv_delimiter,
        ]
        if profile:
            cmd.extend([ '-C', profile ])

        for option, value in options.items():
            cmd.extend( [ '-o', option + ":" + str(value) ])

        if read_filter:
            cmd.extend(['-R', read_filter])

        cmd.extend(['-T', 'fields'])
        for f in fields_to_export:
            cmd.extend([ '-e', f])
        return cmd
