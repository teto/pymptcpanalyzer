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

# faudrait un script pour mapper les ids au columnheader 
MPTCP_FIELD_ID=4
TCP_FIELD_ID=3

# ensuite on passe direct la sortie à gnuplot ? 
# pas pratique pr le debug

# avec l'option -hdr on peut rajouter un header au fichier de sortie
# (-r => range)
csvfix find -f ${MPTCP_FIELD_ID} -r ${MPTCP_STREAM_ID}:${MPTCP_STREAM_ID} $INPUT > mappings.find.csv
# sort numerically
csvfix sort -rh -f ${TCP_FIELD_ID}:AN mappings.find.csv > mappings.sorted.csv
cat mappings.sorted.csv | csvfix write_multi -m ${TCP_FIELD_ID} -rs '\n' -smq > mappings.multi.csv

# then launch gnuplot 

# gnuplot 
# mappings.csv
