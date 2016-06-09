#!/usr/bin/env python3.5
import logging
import subprocess
import os
import tempfile
from typing import List

from enum import Enum

log = logging.getLogger(__name__)


class Filetype(Enum):
    unsupported = 0
    pcap = 1
    sql = 2
    csv = 3


class TsharkExporter:
    """
    TODO 
    in fact we could convert towards all formats supported by pandas:
    http://pandas.pydata.org/pandas-docs/stable/api.html#id12
    
    if you plan to add several options, you should use a specific profile instead, 
    these options are meant to override a base profile
    """
    options = { 
        # used to be 'column.format' in older versions
        # "tshark -G column-formats" list available formats 
        # name is then considered as a field accessible via  -e _ws.col.<name>
        # %Cus => Custom
        # doc on this is not good, you have to check each function, for isntance: col_set_rel_time
        # https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob;f=epan/column.c;h=5d3263d6ce0a814ae2480741e7233130cf0694e6;hb=HEAD
        # rd => resolved
        "gui.column.format": '"Time","%Cus:frame.time","ipsrc","%s","ipdst","%d"',
        # "tcp.relative_sequence_numbers": True if tcp_relative_seq else False,
        "mptcp.analyze_mappings" : True,
# "nameres.hosts_file_handling": True,
# nameres.use_external_name_resolver: True,
# nameres.network_name: True
        "mptcp.relative_sequence_numbers" : True,
        "mptcp.intersubflows_retransmission": True,
        # Disable DSS checks which consume quite a lot
        "mptcp.analyze_mptcp": True,
    }


    def __init__(self, tshark_bin="wireshark", delimiter="|", profile=None):
        """
        :param profile wireshark profiles will setup everything as it should except the gui column format that 
        will be overriden to ensure compatibility with dissection system
        """
        self.tshark_bin = tshark_bin
        # self.fields_to_export = fields_to_export
        self.delimiter = delimiter
        self.profile = profile

    @staticmethod
    def get_default_options():
        """
        """
        options = {}
        return options

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


    def export_to_csv(self, input_filename: str, output_csv : str,
            fields_to_export : List[str], tshark_filter : str =None):
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

        return self.tshark_export_fields(
            self.tshark_bin, 
            fields_to_export, 
            input_filename,
            output_csv,
            tshark_filter,
            profile=self.profile,
            csv_delimiter=self.delimiter,
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
        inputFilename, 
        outputFilename, 
        filter=None, 
        profile=None,
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

        # print(fields_to_export)
        # for some unknown reasons, -Y does not work so I use -2 -R instead
        # quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
        # single-quotes, n no quotes (the default).
        #  -E quote=n 
        # the -2 is very important, else some mptcp parameters are not exported
        # TODO try with -w <outputFile> ?
        cmd = ("{tsharkBinary} {profile} {tsharkOptions} {filterExpression}"
               " -r {inputPcap} -T fields {fieldsExpanded} -E separator='{delimiter}'"
               " -E header=y  -2 "
               " > {outputFilename}").format(
            tsharkBinary=tshark_exe,
            profile=" -C %s" % profile if profile else "",
            tsharkOptions=convert_options_into_str(options),
            inputPcap=inputFilename,
            outputCsv=outputFilename,
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


# TODO replace with pandas export
def convert_csv_to_sql(csv_filename, database, table_name):
    """
    TODO this should be done using pandas library
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
            log.error(e)
            output = "Failure" + str(e)

    return output
