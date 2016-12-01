import os
from typing import List, Tuple
import logging


log = logging.getLogger("mptcpanalyzer")


"""
Similar to config
"""
cache = None # type: Cache

# TODO rename
class Cache:
    """
    TODO copy from doc
    """

    def __init__(self, folder, disabled=False):
        self.folder = folder
        os.makedirs(self.folder, exist_ok=True)
        self.disabled = disabled


    # self.csv_cachename)
    # , translator=str)
    # translator: converts filename to a specific
    def is_cache_valid(self, filename, depends: List[str]=None) -> Tuple[bool, str]:
        """
        Args:
            metadata:
            depends: List of files to check

        Returns:
            A tuple of (True if cache exists, encoded cachename)

        """
        log.debug("Checking cache for %s" % filename)
        is_cache_valid = False

        # todo rename to encode rather
        # cachename = self.matching_cache_filename(filename)
        if depends is None:
            depends = [filename]

        cachename = self.cacheuid(filename)

        if self.disabled:
            log.debug("Cache disabled, hence requested cache deemed invalid")
        elif os.path.isfile(cachename):
            log.info("A cache %s was found" % cachename)
            ctime_cached = os.path.getctime(cachename)
            # ctime_pcap = os.path.getctime(filename)
            # print(ctime_cached , " vs ", ctime_pcap)
            is_cache_valid = True
            for dependancy in depends:
                ctime_dep = os.path.getctime(dependancy)

                if ctime_cached >= ctime_dep:
                    log.debug("Cache dependancy %s ctime (%s) is valid (>= %s)" 
                            % (dependancy, ctime_dep, ctime_cached))
                else:
                    log.debug("Cache outdated by dependancy %s" % dependancy)
                    is_cache_valid = False
                    break

            # then we check if metadata matches
        else:
            log.debug("No cache %s found" % cachename)
        # return is_cache_valid, cachename
        return is_cache_valid

    # def csv_cachename(self, filename):
    #     """
    #     Expects a realpath else
    #     """
    #     # create a list of path elements
    #     # from the absolute filename
    #     l = os.path.realpath(filename).split(os.path.sep)
    #     res = os.path.join(self.folder, '%'.join(l))
    #     # _, ext = os.path.splitext(filename)
    #     # if ext != ".csv":
    #     #     res += ".csv"
    #     return res


    def cacheuid(self, filename):
        """
        generate from filename a unique uuid
        """

        # encode path to cache
        chunks = os.path.realpath(filename).split(os.path.sep)
        return os.path.join(self.folder, '%'.join(chunks))

    def clean(self):
        log.info("Cleaning cache [%s]" % self.folder)
        for cached_csv in os.scandir(self.folder):
            log.info("Removing " + cached_csv.path)
            os.unlink(cached_csv.path)
