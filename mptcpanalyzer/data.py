#!/usr/bin/env python
# -*- coding: utf-8 -*-

log = logging.getLogger("mptcpanalyzer")

def get_matching_csv_filename(filename, regen : bool= False):
    """
    Accept either a .csv or a .pcap file 
    Returns resulting csv filename
    """
    basename, ext = os.path.splitext(filename)
    print("Basename=%s" % basename)
    csv_filename = filename

    if ext == ".csv":
        pass
    else:
        print("%s format is not supported as is. Needs to be converted first" %
            (filename))
        csv_filename = filename + ".csv"  #  str(Filetype.csv.value)
        cache = os.path.isfile(csv_filename)
        if cache:
            log.info("A cache %s was found" % csv_filename)
        # if matching csv does not exist yet or if generation forced
        if not cache or regen:
            log.info("Preparing to convert %s into %s" %
                    (filename, csv_filename))

            exporter = TsharkExporter(
                    self.config["DEFAULT"]["tshark_binary"], 
                    delimiter=delimiter
                )
            retcode, stderr = exporter.export_to_csv(
                    filename, csv_filename, 
                    get_default_fields().keys(),
                    tshark_filter="mptcp and not icmp"
            )
            print("exporter exited with code=", retcode)
            if retcode:
                raise Exception(stderr)
    return csv_filename


@staticmethod
def map_subflows_between_2_datasets(ds1,ds2):
    """
    TODO maybe pass an iterable with tuple of mptcpstreams ?
        ds1 = ds1[(ds1.mptcpstream == args.mptcp_client_id)]        
        ds2 = ds2[ds2.mptcpstream == args.mptcp_server_id]

    Takes 2 datasets ALREADY FILTERED and returns 
    # a dictiorary mapping
    -> a list of tuples
    ds1 TCP flows to ds2 TCP flows
    """
    
    tcpstreams1 = ds1.groupby('tcpstream')
    tcpstreams2 = ds2.groupby('tcpstream')
    print("ds1 has %d subflow(s)." % (len(tcpstreams1)))
    print("ds2 has %d subflow(s)." % (len(tcpstreams2)))
    if len (tcpstreams1) != len(tcpstreams2):
        print("FISHY: Datasets contain a different number of subflows")

    # To filter the dataset, you can refer to 
    mappings = []
    for tcpstream1, gr2 in tcpstreams1:
        # for tcpstream2, gr2 in tcpstreams2:
        # look for similar packets in ds2
        print ("=== toto")

        # result = ds2[ (ds2.ipsrc == gr2['ipdst'].iloc[0])
             # & (ds2.ipdst == gr2['ipsrc'].iloc[0])
             # & (ds2.sport == gr2['dport'].iloc[0])
             # & (ds2.dport == gr2['sport'].iloc[0])
             # ]
        # should be ok
        sf = MpTcpSubflow ( gr2['ipsrc'].iloc[0], gr2['ipdst'].iloc[0],
                gr2['sport'].iloc[0], gr2['dport'].iloc[0])

        result = ds2[ (ds2.ipsrc == sf.ipsrc)
             & (ds2.ipdst == sf.ipdst)
             & (ds2.sport == sf.sport)
             & (ds2.dport == sf.dport)
             ]

        if len(result):
            print ("=== zozo")
            entry = tuple([tcpstream1, result['tcpstream'].iloc[0], sf])
            # print("Found a mapping %r" % entry) 
            mappings.append(entry)

            print("match for stream %s" % tcpstream1)
        else:
            print("No match for stream %s" % tcpstream1)

            # TODO use a print function ?
            line = "\ttcp.stream {tcpstream} : {srcip}:{sport} <-> {dstip}:{dport}".format(
                tcpstream=tcpstream1,
                srcip=gr2['ipsrc'].iloc[0],
                sport=gr2['sport'].iloc[0], 
                dstip=gr2['ipdst'].iloc[0], 
                dport=gr2['dport'].iloc[0]
                )
            print(line)
    return mappings


# TODO move to core or make static 
def load_into_pandas(input_file):
    """
    intput_file must be csv
    """
    csv_filename = get_matching_csv_filename(input_file)



    def _get_dtypes(d):
        ret = dict()
        for key, val in d.items():
            if isinstance(val, tuple) and len(val) > 1:
                ret.update( {key:val[1]})
        return ret
    
    dtypes = _get_dtypes(get_default_fields())
    print("==dtypes", dtypes)
    # TODO use nrows=20 to read only 20 first lines
    # TODO use dtype parameters to enforce a type
    data = pd.read_csv(csv_filename, sep=delimiter, ) #dtype=dtypes)
    # data = pd.read_csv(csv_filename, sep=delimiter, engine="c", dtype=dtypes)
    # print(data.dtypes)

    def _get_wireshark_mptcpanalyzer_mappings(d):
        def name(s):
            return s[0] if isinstance(s, tuple) else s
        # return map(name, d.values())
        return dict( zip( d.keys(), map(name, d.values()) ) )
        # return dict((v,a) for k,a,*v in a.iteritems())

    # print("== tata", dict(get_default_fields()))
    toto = _get_wireshark_mptcpanalyzer_mappings( get_default_fields() )
    # print("== toto", toto)

    data.rename (inplace=True, columns=toto)

    data.tcpseq = data.apply(pd.to_numeric, errors='coerce')
    data.tcpflags.apply(lambda x: int(x,16), )
    # print(data.dtypes)
    # todo let wireshark write raw values and rename columns here
    # along with dtype
    # f.rename(columns={'$a': 'a', '$b': 'b'}, inplace=True)
    columns = list(data.columns)
    print("==column names:", columns)
    # for field in mandatory_fields:
    #     if field not in columns:
    #         raise Exception(
    #             "Missing mandatory field [%s] in csv, regen the file or check the separator" % field)
    print("== before returns\n", data.dtypes)
    return data