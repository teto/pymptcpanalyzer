#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import csv
from mptcpanalyzer import fields_to_export



def build_csv_header_from_list_of_fields(fields,csv_delimiter):
    """
    fields should be iterable
    Returns "field0,field1,..."
    """
    # def strip_fields(fields):
    #   return [ field.split('.')[-1] for field in fields ]
    # return (','.join( strip_fields(fields)) + '\n'  ).encode()
    return csv_delimiter.join(fields) + '\n'

def sniff_csv_fields(csv_file):
	"""
	"""
	with open(csv_file) as f:
		reader = csv.DictReader(f, delimiter="|");

		print("fieldnames:\n", reader.fieldnames)
		print( dir(reader))

def get_column_id(field_name):
	"""
	Return index of column (0-based)
	"""
	try:
		return fields_to_export.index(field_name)
	except ValueError as e:
		return -1
