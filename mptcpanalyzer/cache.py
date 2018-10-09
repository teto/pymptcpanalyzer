import os
from typing import Collection, Union, Any, Tuple
import logging
import shutil
from pathlib import Path


"""
Similar to config
"""

class CacheId:
    def __init__(self, prefix: str,
        filedeps: Collection = [Union[str, Path]],
        suffix: str = "") -> None:
        """
        Builds a cache 'prefix_dep1_dep2_suffix'
        """
        assert len(filedeps) > 0, "without dependency, why use cache ?"

        # TODO apply only to Path type
        # TODO os.path.isabs()
        self.dependencies = list(map(os.path.realpath, filedeps))
        logging.debug("%r %r", prefix, suffix)
        self.tpl = prefix + "_".join([os.path.basename(dep) for dep in filedeps]) + '%s' + str(suffix)

    @property
    def filename(self,):
        """
        generate a unique uuid
        hash modification time of dependencies too
        dependencies should be filename
        """
        dependencies = self.dependencies
        logging.debug("Computing uid from dependencies %r" % dependencies)
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
        dependencies = uid.dependencies

        try:
            if self.disabled:
                logging.debug("Cache disabled")
                return False, cachename

            if os.path.isfile(cachename):
                logging.debug("A cache %s was found" % cachename)
                ctime_cached = os.path.getctime(cachename)
                is_cache_valid = True
                for dependency in dependencies:

                    mtime_dep = os.path.getmtime(dependency)  # type: ignore

                    if ctime_cached >= mtime_dep:
                        logging.debug("Cache dependency %s ctime (%s) is valid (>= %s)"
                            % (dependency, mtime_dep, ctime_cached))
                    else:
                        logging.debug("Cache outdated by dependency %s" % dependency)
                        is_cache_valid = False
                        break
            else:
                logging.debug("No cache %s found" % cachename)
        except Exception as e:
            logging.debug("Invalid cache: %s" % e)
            is_cache_valid = False
            # cachename = None
        finally:
            return is_cache_valid, cachename

    def put(self, uid: CacheId, result: str):
        """
        Moves 'result' in the cache
        """
        dest = os.path.join(self.folder, uid.filename)

        logging.info("Moving file %s to %s" % (result, dest))
        shutil.move(result, dest)

    @staticmethod
    def cacheuid(prefix: str, dependencies: Collection = [], suffix: str = ""):
        return CacheId(prefix, dependencies, suffix)

    def clean(self):
        logging.info("Cleaning cache [%s]" % self.folder)
        for cached_csv in os.scandir(self.folder):
            logging.info("Removing " + cached_csv.path)
            os.unlink(cached_csv.path)

    # helpers to generate specific uids
    @staticmethod
    def merged_uid(pcap1, pcap2, stream1, stream2, suffix):
        return CacheId("owd", [pcap1, pcap2, stream1, stream2], suffix)
