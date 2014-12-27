#!/usr/bin/bash

MPTCP_FIELD_ID=$(./get_column_id mptcpstream)
TCP_FIELD_ID=$(./get_column_id tcpstream)
PACKET_FIELD_ID=$(./get_column_id packetid)
TIME_FIELD_ID=$(./get_column_id time)

CSV_DELIMITER='|'