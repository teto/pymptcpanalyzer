#!/usr/bin/env python3
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

    def __init__(self, tshark_bin="wireshark", delimiter="|", profile=None):
        """
        Args:
            profile: wireshark profiles will setup everything as it should
                except the gui column format that will be overriden to ensure
                compatibility with dissection system
        """
        self.tshark_bin = tshark_bin
        # self.fields_to_export = fields_to_export
        self.delimiter = delimiter
        self.profile = profile
        self.filter = ""  # mptcp ...
        self.options = {
            # used to be 'column.format' in older versions
            # "tshark -G column-formats" list available formats
            # name is then considered as a field accessible via  -e _ws.col.<name>
            # %Cus => Custom
            # see epan/column.c / col_set_rel_time
            "gui.column.format": '"Time","%Cus:frame.time","ipsrc","%s","ipdst","%d"',
            # "tcp.relative_sequence_numbers": True if tcp_relative_seq else False,
            "mptcp.analyze_mappings": True,
            # "nameres.hosts_file_handling": True,
            # nameres.use_external_name_resolver: True,
            # nameres.network_name: True
            "mptcp.relative_sequence_numbers": True,
            "mptcp.intersubflows_retransmission": True,
            # Disable DSS checks which consume quite a lot
            "mptcp.analyze_mptcp": True,
        }
        self.fields = []  # type: List[Field]
        self.add_basic_fields()

    def add_basic_fields(self):
        self.add_field("frame.number", "packetid", np.int64, False, )
        # TODO set tot datetime ?
        self.add_field("frame.time_relative", "reltime", None, False, )
        # set to deltatime
        self.add_field("frame.time_delta", "time_delta", None, False, )
        self.add_field("frame.time_epoch", "abstime", None, False, )
        self.add_field("_ws.col.ipsrc", "ipsrc", str, False, )
        self.add_field("_ws.col.ipdst", "ipdst", str, False, )
        self.add_field("ip.src_host", "ipsrc_host", str, False)
        self.add_field("ip.dst_host", "ipdst_host", str, False)
        # set to categorical ?
        # self.add_field("mptcp.client", "direction", np.float64, False)
        # "mptcp.rawdsn64":        "dsnraw64"
        # "mptcp.ack":        "dack"
        self.add_field("tcp.stream", "tcpstream", np.float64, False)
        self.add_field("tcp.srcport", "sport", np.float, False)
        self.add_field("tcp.dstport", "dport", np.float, False)
        # rawvalue is tcp.window_size_value
        # tcp.window_size takes into account scaling factor !
        self.add_field("tcp.window_size", "rwnd", np.float64, True)
        self.add_field("tcp.flags", "tcpflags", np.int64, False)
        self.add_field("tcp.seq", "tcpseq", np.float64, "TCP sequence number")
        self.add_field("tcp.len", "tcplen", np.float64, "TCP segment length")
        self.add_field("tcp.ack", "tcpack", np.float64, "TCP segment acknowledgment")
        self.add_field("tcp.options.timestamp.tsval", "tcptsval", np.float64, "TCP timestamp tsval")
        self.add_field("tcp.options.timestamp.tsecr", "tcptsecr", np.float64, "TCP timestamp tsecr")

    def add_mptcp_fields(self, advanced=False):
        self.add_field("mptcp.expected_token", "expected_token", str, False)
        self.add_field("mptcp.stream", "mptcpstream", np.float, False)
        self.add_field("tcp.options.mptcp.sendkey", "sendkey", np.float64, False)
        self.add_field("tcp.options.mptcp.recvkey", "recvkey", None, False)
        self.add_field("tcp.options.mptcp.recvtok", "recvtok", None, False)
        self.add_field("tcp.options.mptcp.datafin.flag", "datafin", np.float, False)
        self.add_field("tcp.options.mptcp.subtype", "subtype", np.object, False)
        self.add_field("tcp.options.mptcp.rawdataseqno", "dss_dsn", np.float64, "DSS Sequence Number")
        self.add_field("tcp.options.mptcp.rawdataack", "dss_rawack", np.float64, "DSS raw ack")
        self.add_field("tcp.options.mptcp.subflowseqno", "dss_ssn", np.float64, "DSS Subflow Sequence Number")
        self.add_field("tcp.options.mptcp.datalvllen", "dss_length", np.float64, "DSS length")
        self.add_field("tcp.options.mptcp.addrid", "addrid", None, False)
        self.add_field("mptcp.master", "master", bool, False)
        self.add_field("mptcp.rawdsn64", "dsnraw64", np.float64, "Raw Data Sequence Number")
        self.add_field("mptcp.ack", "dack", np.float64, "MPTCP relative Ack")
        self.add_field("mptcp.dsn", "dsn", np.float64, "Data Sequence Number")

    # def add_retransmission_fields(self):
        if advanced:
            self.add_field("mptcp.related_mapping", "related_mappings", None, "DSS")
            self.add_field("mptcp.duplicated_dsn", "reinjections", None, "Reinjections")
            # TODO use new names
            # self.add_field("mptcp.reinjection_of", "reinjection_of", None, "Reinjection")
            # self.add_field("mptcp.reinjection_listing", "reinjected_in", None, "Reinjection list")

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
            self.filter,
            profile=self.profile,
            csv_delimiter=self.delimiter,
            options=self.options,
        )
        print(cmd)

        try:
            # TODO serialize wireshark options in header
            # with open(output_csv, "w+") as fd:
            fd = output_csv
            fd.write("# metadata: \n")
            fd.flush()  # need to flush else order gets messed up
            proc = subprocess.Popen(cmd, stdout=fd, stderr=subprocess.PIPE, shell=True)
            out, stderr = proc.communicate()
            stderr = stderr.decode("UTF-8")
            print("stderr=", stderr)

        except subprocess.CalledProcessError as e:
            log.error(str(e))
            print("ERROR")
            output = " ehllo "
        return proc.returncode, stderr

    def hash(self,):
        cmd = self.generate_command(
            self.tshark_bin,
            self.get_fields('name'), # TODO convert to list
            "PLACEHOLDER",
            self.filter,
            profile=self.profile,
            csv_delimiter=self.delimiter,
            options=self.options,
        )
        return hash(cmd)

    def export_to_sql(self, input_pcap, output_db, table_name="connections"):
        """
        SQL export possible from pcap or csv (i.e. pcap will be converted first to CSV)
        """

        log.info("Converting pcap [{pcap}] to sqlite database [{db}]".format(
            pcap=input_pcap,
            db=output_db
        ))

        # csv_filename = get_basename(output_db, "csv")
        csv_filename = output_db + ".csv"
        self.export_pcap_to_csv(input_pcap, csv_filename)

        convert_csv_to_sql(csv_filename, output_db, table_name)

    @staticmethod
    def generate_command(
        tshark_exe,
        fields_to_export: List[str],
        inputFilename,
        filter=None,
        profile=None,
        csv_delimiter='|',
        options={},
    ):
        """
        """
        def convert_field_list_into_tshark_str(fields):
            """
            TODO fix if empty
            """
            return ' -e ' + ' -e '.join(fields)

        # fields that tshark should export
        # exhaustive list https://www.wireshark.org/docs/dfref/f/frame.html
        # to filter connection
        filter = ' -R "%s"' % (filter) if filter else ''

        def convert_options_into_str(options):
            """
            Expects a dict of wireshark options
            TODO maybe it could use **kwargs instead
            """
            # relative_sequence_numbers = False
            out = ""
            for option, value in options.items():
                out += ' -o {option}:{value}'.format(option=option, value=value)
            return out

        # for some unknown reasons, -Y does not work so I use -2 -R instead
        # quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
        # single-quotes, n no quotes (the default).
        #  -E quote=n
        # the -2 is very important, else some mptcp parameters are not exported
        # TODO try with -w <outputFile> ?
        tpl = ("{tsharkBinary} {profile} {tsharkOptions} {filterExpression}"
               " -T fields {fieldsExpanded} -E separator='{delimiter}'"
               " -E header=y  -2 "
               " -r {inputPcap}"
        )

        cmd = tpl.format(
            tsharkBinary=tshark_exe,
            profile=" -C %s" % profile if profile else "",
            tsharkOptions=convert_options_into_str(options),
            inputPcap=inputFilename,
            fieldsExpanded=convert_field_list_into_tshark_str(fields_to_export),
            filterExpression=filter,
            delimiter=csv_delimiter,
            # outputFilename=output
        )
        return cmd


# TODO replace with pandas export
def convert_csv_to_sql(csv_filename, database, table_name):
    """
    TODO this should be done using pandas library
    Then you can run SQL commands via SQLite Manager (firefox addo
    """
    log.info("Converting csv to sqlite table {table} into {db}".format(
        table=table_name,
        db=database
    ))
    # db = sqlite.connect(database)
    # For the second case, when the table already exists,
    # every row of the CSV file, including the first row, is assumed to be actual content.
    # If the CSV file contains an initial row of column labels, that row will be read as data
    # and inserted into the table.
    # To avoid this, make sure that table does not previously exist.
    #
    init_command = (
        "DROP TABLE IF EXISTS {table};\n"
        ".separator {delimiter}\n"
        # ".mode csv\n"
        ".import {csvFile} {table}\n"
    ).format(delimiter="|",
             csvFile=csv_filename,
             table=table_name)
    log.info("Creating db %s (if does not exist)" % database)
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        # with open(tempInitFilename, "w+") as f:
        f.write(init_command)
        f.flush()

        cmd = "sqlite3 -init {initFilename} {db} ".format(
            initFilename=f.name,
            db=database,
        )

        log.info("Running command:\n%s" % cmd)
        try:
            output = subprocess.check_output(cmd,
                                             input=".exit".encode(),
                                             shell=True)
        except subprocess.CalledProcessError as e:
            log.error("%s" % e)
            output = "Failure" + str(e)

    return output
