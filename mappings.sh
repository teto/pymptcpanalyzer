#!/bin/bash
# use this during the tests 
# MPTCP connection 5 has 26 packets, with only 1 subflow
# MPTCP connection 0 has 43 packets, with 3 subflows
# bash -x ~/mptcpanalyzer/mappings.sh test.csv 0
if [ $# -lt 2 ]; then
	echo "Use: $0 <inputcsv> <mptcpstream_id>"
	exit 1
fi

INPUT="$1"
MPTCP_STREAM_ID=$2
# make it configurable ?
OUTPUT="output.csv"

# source core.sh
# faudrait un script pour mapper les ids au columnheader 
# MPTCP_FIELD_ID=$(./get_column_id mptcpstream)
# TCP_FIELD_ID=$(./get_column_id tcpstram)

source common.sh

# ensuite on passe direct la sortie à gnuplot ? 
# pas pratique pr le debug
echo stream id ${MPTCP_FIELD_ID}
# {MPTCP_FIELD_ID}
# avec l'option -hdr on peut rajouter un header au fichier de sortie
# (-r => range)
# ifn => Ignore Field Name (1st line)
csvfix find -ifn -f ${MPTCP_FIELD_ID} -sep ${CSV_DELIMITER} -osep ${CSV_DELIMITER} -r ${MPTCP_STREAM_ID}:${MPTCP_STREAM_ID} -o mappings.find.csv $INPUT 
# sort numerically
csvfix sort -f ${TCP_FIELD_ID}:AN -sep ${CSV_DELIMITER} -osep ${CSV_DELIMITER} -o mappings.sorted.csv mappings.find.csv 
cat mappings.sorted.csv | csvfix write_multi -m ${TCP_FIELD_ID} -rs "  " -sep ${CSV_DELIMITER} -osep ${CSV_DELIMITER} -smq > mappings.multi.csv

# then launch gnuplot 

# gnuplot 
# mappings.csv
