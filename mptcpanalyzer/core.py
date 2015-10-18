#!/usr/bin/env python
# -*- coding: utf-8 -*-
# import os
import csv
import json
# from mptcpanalyzer import fields_to_export


def load_fields_to_export_from_file(file_):
    """
    Returns list of fields to export, EOL does not matter
    TODO check it s a list
    """
    import json

    # with open(filename, newline=None) as input:
    with file_ as input:
        # results = list(csv.reader(inputfile))
        return json.load(input)

    raise RuntimeError("error")




def sniff_csv_fields(csv_file):
    """
    """
    with open(csv_file) as f:
        reader = csv.DictReader(f, delimiter="|")

        print("fieldnames:\n", reader.fieldnames)
        print(dir(reader))

# def get_column_id(field_name):
#   """
#   Return index of column (0-based)
#   """
#   try:
#       return fields_to_export.index(field_name)
#   except ValueError as e:
#       return -1
