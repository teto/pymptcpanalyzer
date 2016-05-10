import json

def get_dtypes(d):
    """
    d being a dict with values as tuples, select item 1 of tuple

    """
    ret = dict()
    for key, val in d.items():
        if isinstance(val, tuple) and len(val) > 1:
            ret.update( {key:val[1]})
    return ret


class MpTcpTopology:
    """
    subflow configuration
    """
    
    data

    def __init__(self):
        pass

    def load_topology(filename):

        print("topology=", filename ) 
        with open(filename) as f:
            self.data = json.load(f)

    def print(self):

            print("Number of subflows=%d" % len(j["subflows"]))
            for s in j["subflows"]:
                print("MSS=%d" % s["mss"])
            print("toto")


