#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os


def get_basename(fullname, ext):
    return os.path.splitext(os.path.basename(fullname))[0] + "." + ext


def build_csv_header_from_list_of_fields(fields):
    """
    fields should be iterable
    Returns "field0,field1,..."
    """
    # def strip_fields(fields):
    #   return [ field.split('.')[-1] for field in fields ]
    # return (','.join( strip_fields(fields)) + '\n'  ).encode()
    return ','.join(fields) + '\n'
