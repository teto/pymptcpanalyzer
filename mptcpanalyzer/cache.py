"""
Cache docstring
"""
import os
from typing import Collection, Union, Tuple, List
import logging
import shutil
from pathlib import Path
from mptcpanalyzer.version import __version__

log = logging.getLogger(__name__)

class CacheId:
    '''
    Identifer for any element in the cache
    '''
    def __init__(
        self, prefix: str,
        filedeps: List[str],
        suffix: str = ""
    ) -> None:
        """
        Builds a cache 'prefix_dep1_dep2_suffix'
        """
        assert filedeps, "without dependency, why use cache ?"

        # TODO apply only to Path type
        self.filedeps = list(map(os.path.realpath, filedeps))
        log.debug("%r %r", prefix, suffix)
        self.tpl = prefix + "_".join(
            [os.path.basename(dep) for dep in filedeps]
        ) + '{hash}' + str(suffix)

    @property
    def filename(self,):
        """
        generate a unique uuid
        hash modification time of filedeps too
        filedeps should be filename
        """
        filedeps = self.filedeps
        log.debug("Computing uid from filedeps %r", filedeps)
        temp = ""
        for dep in filedeps:
            mtime_dep = os.path.getmtime(dep)
            temp = temp + dep + str(mtime_dep)

        # append global filedeps such as mptcpanalyzer version
        temp = temp + __version__

        return self.tpl.format(hash=str(hash(temp)))


class Cache:
    """
    1/ generate an id via cacheuid
    2/ if get returns false, generate the file and use put
    """
    def __init__(self, folder, disabled=False) -> None:
        self.folder = folder
        os.makedirs(self.folder, exist_ok=True)
        self.disabled = disabled

    def get(self, uid: CacheId) -> Tuple[bool, str]:
        """
        Returns:
            validity, outPath
        """

        is_cache_valid = False
        cachename = os.path.join(self.folder, uid.filename)
        filedeps = uid.filedeps

        try:
            if self.disabled:
                log.debug("Cache disabled")
                return False, cachename

            if os.path.isfile(cachename):
                log.debug("A cache %s was found", cachename)
                ctime_cached = os.path.getctime(cachename)
                is_cache_valid = True
                for dependency in filedeps:

                    mtime_dep = os.path.getmtime(dependency)  # type: ignore

                    if ctime_cached >= mtime_dep:
                        log.debug("Cache dependency %s ctime (%s) is valid (>= %s)",
                            dependency, mtime_dep, ctime_cached)
                    else:
                        log.debug("Cache outdated by dependency %s", dependency)
                        is_cache_valid = False
                        break
            else:
                log.debug("No cache %s found", cachename)

        except Exception as e:
            log.debug("Invalid cache: %s", e)
            is_cache_valid = False

        return is_cache_valid, cachename

    def put(self, uid: CacheId, result: str):
        """
        Moves 'result' in the cache
        """
        dest = os.path.join(self.folder, uid.filename)

        log.info("Moving file %s to %s", result, dest)
        shutil.move(result, dest)

    @staticmethod
    def cacheuid(prefix: str, filedeps: List = None, suffix: str = ""):
        '''Generates a cache id for the item'''
        if not filedeps:
            filedeps = []

        return CacheId(prefix, filedeps, suffix)

    def clean(self):
        '''Removes everything from cache'''
        log.info("Cleaning cache [%s]", self.folder)
        for cached_csv in os.scandir(self.folder):
            log.info("Removing %s", cached_csv.path)
            os.unlink(cached_csv.path)

    # helpers to generate specific uids
    @staticmethod
    def merged_uid(pcap1, pcap2, stream1, stream2, suffix):
        return CacheId("owd", [pcap1, pcap2, stream1, stream2], suffix)
