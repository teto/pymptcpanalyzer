#!/usr/bin/env python
import logging
import subprocess
import tempfile

from mptcpanalyzer.core import build_csv_header_from_list_of_fields 
from mptcpanalyzer import fields_dict, fields_to_export, get_basename

log = logging.getLogger(__name__)


class TsharkExporter:

    input_pcap = ""
    tshark_bin = None
    tcp_relative_seq = True
    delimiter = '|'

    # TODO should be settable
    filter = "mptcp.stream"

    def __init__(self, tshark_bin="/usr/bin/wireshark"):
        self.tshark_bin = tshark_bin
        self.fields_to_export = fields_to_export
        pass

    def export_pcap_to_csv(self, inputPcap, outputCsv):
        """
        """
        log.info("Converting pcap [{pcap}] to csv [{csv}]".format(
            pcap=inputPcap,
            csv=outputCsv)
        )

        # TODO should export everything along with TCP acks
        # TODO should accept a filter mptcp stream etc...
        # ands convert some parts of the filter into an SQL request
        # output = ""
        header = build_csv_header_from_list_of_fields(fields_to_export, self.delimiter)
        # print("header:", output)
        # output = output if output else ""
        output = self.tshark_export_fields(
            self.tshark_bin, 
            self.fields_to_export, 
            inputPcap,
            outputCsv,
            self.filter,
            relative_sequence_numbers=self.tcp_relative_seq
        )

        # q.
        # load this into a csv reader
        # with
        # could filter
        log.info("Writing to file")

        with open(outputCsv, "w") as f:
            f.write(header)
            f.write(output.decode())

    def export_pcap_to_sql(self, inputPcap, outputDb, table_name="connections"):
        """
        """

        log.info("Converting pcap [{pcap}] to sqlite database [{db}]".format(
            pcap=inputPcap,
            db=outputDb
        ))

        csv_filename = get_basename(outputDb, "csv")
        self.export_pcap_to_csv(inputPcap, csv_filename)

        convert_csv_to_sql(csv_filename, outputDb, table_name)

    @staticmethod
    def tshark_export_fields(tshark_exe, fields_to_export, 
                             inputFilename, outputFilename, 
                             filter=None, relative_sequence_numbers=False,
                             csv_delimiter='|',):
        """
        inputFilename should be pcap filename
        fields should be iterable (tuple, list ...)
        returns outout as a string
        """
        def convert_into_tshark_field_list(fields):
            return ' -e ' + ' -e '.join([fields_dict[x] for x in fields])
        # fields that tshark should export
        # tcp.seq / tcp.ack / ip.src / frame.number / frame.number / frame.time
        # exhaustive list https://www.wireshark.org/docs/dfref/f/frame.html
        # tcp.options.mptcp.subtype == 2 => DSS (0 => MP-CAPABLE)
        # to filter connection
        filter = '-2 -R "%s"' % (filter) if filter else ''

        options = ' -o tcp.relative_sequence_numbers:TRUE' if relative_sequence_numbers else ''

        print(fields_to_export)
        # for some unknown reasons, -Y does not work so I use -2 -R instead
        # quote=d|s|n Set the quote character to use to surround fields.  d uses double-quotes, s
        # single-quotes, n no quotes (the default).
        #  -E quote=n 
        cmd = """{tsharkBinary} {tsharkOptions} -n {filterExpression} -r {inputPcap} -T fields {fieldsExpanded} -E separator='{delimiter}'""".format(
            tsharkBinary=tshark_exe,
            tsharkOptions=options,
            inputPcap=inputFilename,
            outputCsv=outputFilename,
            fieldsExpanded=convert_into_tshark_field_list(fields_to_export),
            filterExpression=filter,
            delimiter=csv_delimiter
        )

        print(cmd)

        try:
            #https://docs.python.org/3/library/subprocess.html#subprocess.check_output
            output = subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as e:
            log.error(e)
            print("ERROR")
            output = " ehllo "
        # os.system(cmd)
        # except CalledProcessError as e:
        # print(output)
        return output


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
    #For the second case, when the table already exists, 
    # every row of the CSV file, including the first row, is assumed to be actual content. If the CSV file contains an initial row of column labels, that row will be read as data and inserted into the table. To avoid this, make sure that table does not previously exist. 
    #
    initCommand = (
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
    print(initCommand)
    log.info("Creating db %s (if does not exist)" % database)
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        # with open(tempInitFilename, "w+") as f:
        f.write(initCommand)
        f.flush()

        cmd = "sqlite3 -init {initFilename} {db} ".format(
            initFilename=f.name,
            db=database,
            # init=initCommand
        )

        # cmd="sqlite3"
        # tempInitFilename      
        log.info("Running command:\n%s" % cmd)
        # input=initCommand.encode(),
        try:

            output = subprocess.check_output(cmd, 
                                             input=".exit".encode(),
                                             shell=True)
        except subprocess.CalledProcessError as e:
            log.error(e)
            output = "Failure" + str(e)

    return output