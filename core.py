import json



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


