from unittest import TestCase

from mptcpanalyzer.config import MpTcpAnalyzerConfig
from mptcpanalyzer.cache import Cache
import tempfile
import shutil
import os

from pathlib import Path


config_file = "tests/test_config.ini"

class ConfigTest(TestCase):
# TODO check filename loaded correctly

    def test_xdg_config_home(self):
        """
        Override XDG_CONFIG_HOME and checks it's correctly loaded
        """
        #TODO use tempdir
        with tempfile.TemporaryDirectory() as dirname:
            # os.copy
            # TODO check it can work even if XDG_CONFIG_HOME is empty
            cfg = MpTcpAnalyzerConfig()
            shutil.copyfile(
                config_file,
                os.path.join(dirname, os.path.basename(config_file))
            )

            cfg = MpTcpAnalyzerConfig()

    def test_values_are_loaded(self):
        """
        Reads a config file and make sure some default values are ok
        """

        # config = MpTcpAnalyzerConfig()
        cfg = MpTcpAnalyzerConfig(config_file)
        # self.assert
        cfg = cfg["mptcpanalyzer"]
        self.assertEqual(cfg["tshark_binary"], "fake_tshark")
        self.assertEqual(cfg["delimiter"], "|")


class CacheTest(TestCase):


    def test_validity(self):
        # TODO test is_cache_valid with multiple depandancies 

        with tempfile.TemporaryDirectory() as tmpdir:

            f = Path(tmpdir, "toto.txt").touch()
            g = Path(tmpdir, "toto2.txt").touch()
            with tempfile.TemporaryDirectory() as cachedir:
                cache = Cache(cachedir)
                self.assertFalse(cache.is_cache_valid(f.filename), "file does not exist yet")
                uid = cache.cacheuid(f)
                shutil.copy(f.filename, uid)
                self.assertTrue(cache.is_cache_valid(f.filename), "")
                f.unlink()
                f = Path(tmpdir, "toto.txt").touch()
                self.assertFalse(cache.is_cache_valid(f.filename), "Cache is older than file")


    def test_clean(self):

        with tempfile.TemporaryDirectory() as tmpdir:

            cache = Cache(tmpdir)
            Path(tmpdir, "toto.txt").touch()

            self.assertGreater(os.listdir(self.folder), 0, "cache should contain elements")

            cache.clean()
            self.assertEqual(os.listdir(self.folder), 0, "cache should be empty")
