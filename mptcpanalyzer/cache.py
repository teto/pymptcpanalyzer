import os
from typing import Collection, Union, Any
import logging
import shutil
from pathlib import Path


log = logging.getLogger(__name__)


"""
Similar to config
"""
cache = None  # type: Cache

class CacheId:
    def __init__(self, prefix: str,
            deps: Collection=[Union[str, Path]],
            suffix: str="" ) -> None:
        """
        Builds a cache 'prefix_dep1_dep2_suffix'
        """
        assert len(deps) > 0, "without dependency, why use cache ?"

        self.dependencies = list(map(os.path.abspath, deps))
        log.debug("%r %r", prefix, suffix)
        self.tpl = prefix + "_".join([os.path.basename(dep) for dep in deps]) + '%s' + str(suffix)

    @property
    def filename(self,):
        """
        generate a unique uuid
        hash modification time of dependencies too
        dependencies should be filename
        """
        dependencies = self.dependencies
        log.debug("Computing uid from dependencies %r" % dependencies)
        temp = ""
        for dep in dependencies:
            mtime_dep = os.path.getmtime(dep)
            temp = temp + dep + str(mtime_dep)

        return self.tpl % str(hash(temp))


class Cache:
    """
    1/ generate an id via cacheuid
    2/ if get returns false, generate the file and use put
    """
    def __init__(self, folder, disabled=False):
        self.folder = folder
        os.makedirs(self.folder, exist_ok=True)
        self.disabled = disabled

    def get(self, uid: CacheId):

        is_cache_valid = False
        try:
            cachename = os.path.join(self.folder, uid.filename)
            dependencies = uid.dependencies

            if os.path.isfile(cachename):
                log.info("A cache %s was found" % cachename)
                ctime_cached = os.path.getctime(cachename)
                is_cache_valid = True
                for dependency in dependencies:

                    mtime_dep = os.path.getmtime(dependency) # type: ignore

                    if ctime_cached >= mtime_dep:
                        log.debug("Cache dependency %s ctime (%s) is valid (>= %s)"
                            % (dependency, mtime_dep, ctime_cached))
                    else:
                        log.debug("Cache outdated by dependency %s" % dependency)
                        is_cache_valid = False
                        break
            else:
                log.debug("No cache %s found" % cachename)
        except Exception as e:
            log.debug("Invalid cache: %s" % e)
            is_cache_valid = False
            cachename = "invalid"
        finally:
            return is_cache_valid, cachename

    def put(self, uid: CacheId, result: str):
        """
        Moves 'result' in the cache
        """
        dest = os.path.join(self.folder, uid.filename)
        log.info("Moving file %s to %s" % (result, dest))
        shutil.move(result, dest)

    @staticmethod
    def cacheuid(prefix: str, dependencies: Collection=[], suffix: str=""):
        return CacheId(prefix, dependencies, suffix)

    def clean(self):
        log.info("Cleaning cache [%s]" % self.folder)
        for cached_csv in os.scandir(self.folder):
            log.info("Removing " + cached_csv.path)
            os.unlink(cached_csv.path)


    # helpers to generate specific uids
    @staticmethod
    def merged_uid(pcap1, pcap2, stream1, stream2, suffix):
        return CacheId("owd", [ pcap1, pcap2, stream1, stream2], suffix)
