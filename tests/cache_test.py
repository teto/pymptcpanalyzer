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
        # Changing log level to DEBUG
        loglevel = logging.DEBUG
        logging.basicConfig(level=loglevel)

    def test_validity(self):
        # TODO test is_cache_valid with multiple depandancies 

        with tempfile.TemporaryDirectory() as tmpdir:

            f = Path(tmpdir, "toto.txt")
            g = Path(tmpdir, "toto2.txt")
            f.touch()
            with tempfile.TemporaryDirectory() as cachedir:
                print("tmpdir=", tmpdir)
                print("cachedir=%s\n" % cachedir)
                print("f=%s/cachename=" % f)
                cache = Cache(cachedir)
                self.assertFalse(cache.is_cache_valid(f.as_posix()), "cache should not exist yet")
                f_uid = cache.cacheuid(f.as_posix())
                shutil.copy(f.as_posix(), f_uid)
                self.assertTrue(cache.is_cache_valid(f.as_posix()), "cache should be valid")
                # self.assertFalse(cache.is_cache_valid(f.as_posix(), [f.as_posix(), g.as_posix()]), 
                        # "dependancy on g not satisfied (g not created yet)")
                g.touch()
                g_uid = cache.cacheuid(g.as_posix())
                shutil.copy(g.as_posix(), g_uid)
                self.assertTrue(cache.is_cache_valid(f.as_posix(), [f.as_posix(), g.as_posix()]), 
                        "dependancy on g ok")

                # invalidate cache
                f.unlink()
                time.sleep(0.5)
                f = Path(tmpdir, "toto.txt")
                f.touch()
                self.assertFalse(cache.is_cache_valid(f.as_posix()), "Cache should be older than file and thus invalid")


    def test_clean(self):

        with tempfile.TemporaryDirectory() as tmpdir:

            cache = Cache(tmpdir)
            Path(tmpdir, "toto.txt").touch()

            self.assertGreater(len(os.listdir(cache.folder)), 0, "cache should contain elements")

            cache.clean()
            self.assertEqual(len(os.listdir(cache.folder)), 0, "cache should be empty")
