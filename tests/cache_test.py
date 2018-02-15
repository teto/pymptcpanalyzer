from unittest import TestCase

from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.cache import Cache
import logging
import tempfile
import time
import shutil
import os

from pathlib import Path


class CacheTest(TestCase):

    def setUp(self):
        loglevel = logging.DEBUG
        logging.basicConfig(level=loglevel)

    def test_single_dep(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir, "toto.txt")
            f.touch()
            generated_cache = Path(tmpdir, "generated.txt")
            generated_cache.touch()

            with tempfile.TemporaryDirectory() as cachedir:
                cache = Cache(cachedir)
                uid_f = cache.cacheuid("", [f], "")

                res, name = cache.get(uid_f)
                self.assertFalse(res, "cache should not exist yet")

                cache.put(uid_f, generated_cache.as_posix())
                res2, name2 = cache.get(uid_f)
                self.assertTrue(res2, "cache should be valid")

    def test_multiple_dependencies(self):
        with tempfile.TemporaryDirectory() as tmpdir:

            f = Path(tmpdir, "toto.txt")
            g = Path(tmpdir, "toto2.txt")
            generated = Path(tmpdir, "generated.txt")
            generated.touch()
            f.touch()
            g.touch()
            with tempfile.TemporaryDirectory() as cachedir:
                cache = Cache(cachedir)

                uid_g = cache.cacheuid("", [f, g], "")
                cache.put(uid_g, generated.as_posix())
                res3, name3 = cache.get(uid_g)
                self.assertTrue(res3, "multidependancy cache items should be ok")

                # invalidates cache by recreating one of the dependency
                f.unlink()
                time.sleep(0.5)
                f = Path(tmpdir, "toto.txt")
                f.touch()
                res4, name4 = cache.get(uid_g)
                self.assertFalse(res4, "Cache should be older than file and thus invalid")


    def test_clean(self):

        with tempfile.TemporaryDirectory() as tmpdir:

            cache = Cache(tmpdir)
            f = Path("toto.txt")
            uid = cache.cacheuid("prefix", [f], "suffix")
            f.touch()

            cache.put(uid, f.as_posix())
            self.assertGreater(len(os.listdir(cache.folder)), 0, "cache should contain elements")

            cache.clean()
            self.assertEqual(len(os.listdir(cache.folder)), 0, "cache should be empty")
