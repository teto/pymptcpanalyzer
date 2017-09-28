import glob
import os
import logging

# modules = glob.glob(os.path.dirname(__file__) + "/*.py")
# print("Modules", modules)
# __all__ = [os.path.basename(f)[:-3] for f in modules]
# __all__ = ['mappings_vs_ack']
# print("value", __all__)

log = logging.getLogger("mptcpanalyzer")
ch = logging.StreamHandler()

# %(asctime)s - %
formatter = logging.Formatter('%(name)s:%(levelname)s: %(message)s')
ch.setFormatter(formatter)

log.addHandler(ch)
# log.setLevel(logging.DEBUG)


__all__ = ['log']
