import os
from typing import List, Tuple
import logging


log = logging.getLogger("mptcpanalyzer")


"""
Similar to config
"""
cache = None  # type: Cache

# TODO rename
class Cache:
    """
    TODO copy from doc
    """

    def __init__(self, folder, disabled=False):
        self.folder = folder
        os.makedirs(self.folder, exist_ok=True)
        self.disabled = disabled

    def load_from_cache(self, uid):
        pass

    # todo use get() instead
    # def is_cache_valid(self, uid, dependencies: List[str]=None) -> Tuple[bool, str]:
    #     """
    #     Args:
    #         metadata:
    #         depends: List of files to check, useful when a cached file results
    #             from merging several files, to compute OWD for instance

    #     Returns:
    #         A tuple of (True if cache exists, encoded cachename)

    #     """
    #     log.debug("Checking cache for %s" % uid)
    #     is_cache_valid = False

    #     # todo rename to encode rather
    #     # cachename = self.matching_cache_filename(filename)
    #     if dependencies is None:
    #         dependencies = [filename]

    #     cachename = self.cacheuid(filename)

    #     if self.disabled:
    #         log.debug("Cache disabled, hence requested cache deemed invalid")
    #     elif os.path.isfile(cachename):
    #         log.info("A cache %s was found" % cachename)
    #         ctime_cached = os.path.getctime(cachename)
    #         # ctime_pcap = os.path.getctime(filename)
    #         # print(ctime_cached , " vs ", ctime_pcap)
    #         is_cache_valid = True
    #         for dependancy in dependencies:
    #             # todo use mtime instead ?!
    #             ctime_dep = os.path.getctime(dependancy)

    #             if ctime_cached >= ctime_dep:
    #                 log.debug(
    #                     "Cache dependancy %s ctime (%s) is valid (>= %s)"
    #                     % (dependancy, ctime_dep, ctime_cached))
    #             else:
    #                 log.debug("Cache outdated by dependancy %s" % dependancy)
    #                 is_cache_valid = False
    #                 break

    #         # then we check if metadata matches
    #     else:
    #         log.debug("No cache %s found" % cachename)
    #     # return is_cache_valid, cachename
    #     return is_cache_valid

    @staticmethod
    def cacheuid(self, prefix: str, dependencies=[], suffix: str=""):
        """
        generate from filename a unique uuid
        """
        # do a hash of all files in 
        temp = ""
        for dep in dependencies:
            prefix + " " + suffix
            # for dependancy in depends:
            # todo use mtime instead ?!
            mtime_dep = os.path.getmtime(dep)
            temp = temp + dep + str(mtime_dep)

        return prefix + str(hash(temp)) + suffix

        # encode path to cache
        # chunks = os.path.realpath(filename).split(os.path.sep)
        # return os.path.join(self.folder, '%'.join(chunks))

    def clean(self):
        log.info("Cleaning cache [%s]" % self.folder)
        for cached_csv in os.scandir(self.folder):
            log.info("Removing " + cached_csv.path)
            os.unlink(cached_csv.path)
