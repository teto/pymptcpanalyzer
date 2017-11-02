import os
from typing import List, Tuple, Collection
import logging
import shutil
from pathlib import Path


# log = logging.getLogger("mptcpanalyzer")
log = logging.getLogger(__name__)


"""
Similar to config
"""
cache = None  # type: Cache

class CacheId:
    def __init__(self, prefix: str,
            dependencies: Collection=[Path],
            suffix: str="" ) -> None:

        # TODO check all Path exists / .exists()
        self.dependencies = dependencies
        log.debug("%r %r", prefix, suffix)
        self.tpl = prefix + '%s' + str(suffix)

    @property
    def filename(self,):
    # @staticmethod
    # def cacheuid(prefix: str, dependencies: Collection=[], suffix: str=""):
        """
        generate a unique uuid
        dependencies should be filename
        """
        dependencies = self.dependencies
        log.debug("Computing uid from dependencies %r" % dependencies)
        temp = ""
        for dep in dependencies:
            # for dependancy in depends:
            mtime_dep = os.path.getmtime(dep)
            temp = temp + dep + str(mtime_dep)

        return self.tpl % str(hash(temp))
        # return prefix + str(hash(temp)) + str(suffix)

        # encode path to cache
        # chunks = os.path.realpath(filename).split(os.path.sep)
        # return os.path.join(self.folder, '%'.join(chunks))

    # @property
    # def filename(self,).
    #     return Cache.cacheuid()


# TODO rename
class Cache:
    """
    TODO copy from doc
    """

    def __init__(self, folder, disabled=False):
        self.folder = folder
        os.makedirs(self.folder, exist_ok=True)
        self.disabled = disabled

    def get(self, uid: CacheId):

        cachename = cache.folder + uid.filename
        dependencies = uid.dependencies
        is_cache_valid = False

        # if self.disabled:
        #     log.debug("Cache disabled, hence requested cache deemed invalid")
        if os.path.isfile(cachename):
            log.info("A cache %s was found" % cachename)
            ctime_cached = os.path.getctime(cachename)
            # ctime_pcap = os.path.getctime(filename)
            # print(ctime_cached , " vs ", ctime_pcap)
            is_cache_valid = True
            for dependancy in dependencies:
                # todo use mtime instead ?!
                ctime_dep = os.path.getctime(dependancy)

                if ctime_cached >= ctime_dep:
                    log.debug(
                        "Cache dependancy %s ctime (%s) is valid (>= %s)"
                        % (dependancy, ctime_dep, ctime_cached))
                else:
                    log.debug("Cache outdated by dependancy %s" % dependancy)
                    is_cache_valid = False
                    break

            # then we check if metadata matches
        else:
            log.debug("No cache %s found" % cachename)
        # return is_cache_valid, cachename
        return is_cache_valid, cachename

    def put(self, uid: CacheId, result: str):
        shutil.move(result, cache.folder + uid.filename)

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

    @staticmethod
    def cacheuid(prefix: str, dependencies: Collection=[], suffix: str=""):
        return CacheId(prefix, dependencies, suffix)

    def clean(self):
        log.info("Cleaning cache [%s]" % self.folder)
        for cached_csv in os.scandir(self.folder):
            log.info("Removing " + cached_csv.path)
            os.unlink(cached_csv.path)
