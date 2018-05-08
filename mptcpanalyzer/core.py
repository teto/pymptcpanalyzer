import json
import subprocess

def copy_to_x(content):
    """
    Copy to *clipboard*
    http://stackoverflow.com/questions/7606062/is-there-a-way-to-directly-send-a-python-output-to-clipboard
    """
    from subprocess import Popen, PIPE
    p = Popen(['xsel', '-pi'], stdin=PIPE)
    p.communicate(input=content)


def get_dtypes(d):
    """
    d being a dict with values as tuples, select item 1 of tuple

    """
    ret = dict()
    for key, val in d.items():
        if isinstance(val, tuple) and len(val) > 1:
            ret.update({key: val[1]})
    return ret

