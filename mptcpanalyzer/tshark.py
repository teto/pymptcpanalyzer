#!/usr/bin/env python
import logging
import subprocess
import os
import tempfile
# available since python 3.4
from enum import Enum

# from mptcpanalyzer.core import build_csv_header_from_list_of_fields 
# from . import fields_dict
# , get_basename

log = logging.getLogger(__name__)


class Filetype(Enum):
    unsupported = 0
    pcap = 1
    sql = 2
    csv = 3


class TsharkExporter:
    """
    TODO tshark.py devrait plutot accepter des streams

    """

    input_pcap = ""
    tshark_bin = None
    tcp_relative_seq = True
    options = { 
        "column.format": '"Time","%Cus:frame.time"',
        "tcp.relative_sequence_numbers": True if tcp_relative_seq else False,
        "mptcp.analyze_mappings" : True,
        "mptcp.relative_sequence_numbers" : True,
        # "tcp.relative_sequence_numbers": 
        # Disable DSS checks which consume quite a lot
        # "tcp.analyze_mptcp_seq": False,
        # "tcp.analyze_mptcp": True,
        # "tcp.analyze_mptcp_mapping": False,
    }    
    delimiter = '|'
    # fields_to_export = (
    #     "packetid", 
    #     "time",
    #     "mptcpstream", 
    #     "tcpstream", 
    # )

    # TODO should be settable
    # mptcp.stream
    filter = ""

    def __init__(self, tshark_bin="/usr/bin/wireshark", delimiter="|"):
        self.tshark_bin = tshark_bin
        # self.fields_to_export = fields_to_export
        self.delimiter = delimiter

    @staticmethod
    def get_default_options():
        """
        """
        return self.options

    @staticmethod
    def get_default_fields():
        """
        Mapping between short names easy to use as a column title (in a CSV file) 
        and the wireshark field name
        """
        return {
            "packetid": "frame.number",
            "time": "frame.time",
            "reltime": "frame.time_relative",
            "time_delta": "frame.time_delta",
            "ipsrc": "_ws.col.Source",
            "ipdst": "_ws.col.Destination",
            "tcpstream": "tcp.stream",
            "mptcpstream": "mptcp.stream",
            "sport": "tcp.srcport",
            "dport": "tcp.dstport",
            # "sendkey": "tcp.options.mptcp.sendkey",
            # "recvkey": "tcp.options.mptcp.recvkey",
            # "recvtok": "tcp.options.mptcp.recvtok",
            "datafin": "tcp.options.mptcp.datafin.flag",
            "subtype": "tcp.options.mptcp.subtype",
            "tcpflags": "tcp.flags",
            "dss_dsn": "tcp.options.mptcp.rawdataseqno",
            "dss_rawdsn": "tcp.options.mptcp.rawdataseqno",
            "dss_rawack": "tcp.options.mptcp.rawdataack",
            "dss_ssn": "tcp.options.mptcp.subflowseqno",
            "dss_length": "tcp.options.mptcp.datalvllen",
            "master": "mptcp.master",
            "tcpseq": "tcp.seq",
            "dsn": "mptcp.dsn",
            "dack": "mptcp.ack",
            "dataack": "mptcp.ack",
        }

    @staticmethod
    def build_csv_header_from_list_of_fields(fields, csv_delimiter):
        """
        fields should be iterable
        Returns "field0,field1,..."
        csv delimiter will probably be '|' or ','
        """
        return csv_delimiter.join(fields) + '\n'

    @staticmethod
    def find_type(filename):
        """
        \return a Filetype instance
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

    # def convert_to_csv(self, input_filename, output_filename, fields_to_export):
        # pass

    def export_to_csv(self, input_filename, output_csv, fields_to_export=None, filter=None):
        """
        fields_to_export = dict
        Returns exit code, stderr
        """
        log.info("Converting pcap [{pcap}] to csv [{csv}]".format(
            pcap=input_filename,
            csv=output_csv)
        )

        if self.find_type(input_filename) != Filetype.pcap:
            raise Exception("Input filename not a capture file")

        fields_to_export = fields_to_export or self.get_default_fields()
        header = self.build_csv_header_from_list_of_fields(fields_to_export.keys(), self.delimiter)        

        # output = output if output else ""
        log.info("Writing to file %s" % output_csv)
        with open(output_csv, "w") as f:
            f.write(header)

        return self.tshark_export_fields(
            self.tshark_bin, 
            fields_to_export.values(), 
            input_filename,
            output_csv,
            self.filter,
            options=self.options,
            # relative_sequence_numbers=self.tcp_relative_seq
        )

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
    def tshark_export_fields(
        tshark_exe, 
        fields_to_export,
        inputFilename, outputFilename, 
        filter=None, 
        csv_delimiter='|',
        options={},
    ):
        """
        inputFilename should be pcap filename
        fields should be iterable (tuple, list ...)
        returns exit code, stderr
        """
        def convert_field_list_into_tshark_str(fields):
            """
            TODO fix if empty
            """
            return ' -e ' + ' -e '.join(fields)

        # fields that tshark should export
        # exhaustive list https://www.wireshark.org/docs/dfref/f/frame.html
        # to filter connection
        filter = '-2 -R "%s"' % (filter) if filter else ''

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

        print(fields_to_export)
        # for some unknown reasons, -Y does not work so I use -2 -R instead
        # quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
        # single-quotes, n no quotes (the default).
        #  -E quote=n 
        cmd = """{tsharkBinary} {tsharkOptions} {nameResolution} {filterExpression} -r {inputPcap} -T fields {fieldsExpanded} -E separator='{delimiter}' >> {outputFilename}
                 """.format(
            tsharkBinary=tshark_exe,
            tsharkOptions=convert_options_into_str(options),
            nameResolution="-n",
            inputPcap=inputFilename,
            outputCsv=outputFilename,
            # ' -E header=y ' +
            fieldsExpanded=convert_field_list_into_tshark_str(fields_to_export),
            filterExpression=filter,
            delimiter=csv_delimiter,
            outputFilename=outputFilename
        )
        print(cmd)

        try:
            # https://docs.python.org/3/library/subprocess.html#subprocess.check_output
            # output = subprocess.Popen(cmd, shell=True) stdout=subprocess.PIPE, 
            proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, shell=True)
            out, stderr = proc.communicate()
            # out = out.decode("UTF-8")
            stderr = stderr.decode("UTF-8") 
            print("stderr=", stderr)
        except subprocess.CalledProcessError as e:
            log.error(e)
            print("ERROR")
            output = " ehllo "
        # os.system(cmd)
        # except CalledProcessError as e:
        # print(output)
        return proc.returncode, stderr


# Ideally I would have liked to rely on some external library like
# querycsv, csvkit etc... but they all seem broken in one way or another
# https://docs.python.org/3.4/library/sqlite3.html
def convert_csv_to_sql(csv_filename, database, table_name):
    # sqlite3
    # 
    # > .separator ","
    # > .import test.csv TEST
    """
    csv_filename
    csv_content should be a string
    Then you can run SQL commands via SQLite Manager (firefox addo 
    """

    log.info("Converting csv to sqlite table {table} into {db}".format(
        table=table_name,
        db=database
    ))
    # db = sqlite.connect(database)
    # csv_filename
    # For the second case, when the table already exists, 
    # every row of the CSV file, including the first row, is assumed to be actual content. If the CSV file contains an initial row of column labels, that row will be read as data and inserted into the table. To avoid this, make sure that table does not previously exist. 
    #
    init_command = (
        "DROP TABLE IF EXISTS {table};\n"
        ".separator {delimiter}\n"
        # ".mode csv\n"
        ".import {csvFile} {table}\n"
    ).format(delimiter="|",
             csvFile=csv_filename,
             table=table_name)

    # initCommand=
    #     "DROP TABLE IF EXISTS {table};\n"
    #     ".separator '{separator}'\n"
    #         ".import {csvFile} {table}\n").format(
    #         separator=",",
    #         csvFile=csv_filename,
    #         table=table_name
    #         )
    # print(initCommand)
    log.info("Creating db %s (if does not exist)" % database)
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        # with open(tempInitFilename, "w+") as f:
        f.write(init_command)
        f.flush()

        cmd = "sqlite3 -init {initFilename} {db} ".format(
            initFilename=f.name,
            db=database,
            # init=init_command
        )

        # cmd="sqlite3"
        # tempInitFilename      
        log.info("Running command:\n%s" % cmd)
        # input=init_command.encode(),
        try:

            output = subprocess.check_output(cmd, 
                                             input=".exit".encode(),
                                             shell=True)
        except subprocess.CalledProcessError as e:
            log.error(e)
            output = "Failure" + str(e)

    return output
