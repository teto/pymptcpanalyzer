from unittest import TestCase
import unittest
import mptcpanalyzer

#import mptcpanalyzer as mp
#from mptcpanalyzer import load_into_pandas
#from mptcpanalyzer.cli import MpTcpAnalyzer, main
#from mptcpanalyzer.config import MpTcpAnalyzerConfig
#from mptcpanalyzer.connection import MpTcpConnection
#import mptcpanalyzer.data as data
#import mptcpanalyzer.plots as plots
#import pandas as pd
#from stevedore.extension import Extension
#import tempfile
#import shlex
#import shutil
#import logging
#import os
#import pathlib

#mptcp_pcap = "examples/iperf-mptcp-0-0.pcap"
#mptcp_pcap = os.path.abspath("examples/iperf-mptcp-0-0.pcap")

#config_file = os.path.abspath("tests/test_config.ini")

#loglevel = logging.DEBUG


@pytest.fixture
def argparse_app():
    app = mptcpanalyzer.()
    app.stdout = StdOut()
return app

#def oneshot(arguments_to_parse: str):
#    """
#    Used in the testsuite
#    """
#    return main(shlex.split(arguments_to_parse))

 # @unittest.skipIf(mylib.__version__ < (1, 3),
  # @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows")
class IntegrationTest(TestCase):
    """
    Few reminders :
        :w @unittest.expectedFailure
    List of builtin exceptions
    https://docs.python.org/3/library/exceptions.html

   one can use oneshot or 
   z.onecmd()

   Attr:
       cache_folder:
       config:
   """

#    # def oneshot(self, arguments_to_parse: str):
#    #     """
#    #     Used in the testsuite
#    #     """
#    #     # cmd = " --cachedir= --config="
#    #     cmd = ""
#    #     cmd += arguments_to_parse
#    #     return main(shlex.split(cmd))



   @classmethod
   def setUpClass(cls):
       """
       Just called for the class
       """
       logger = logging.getLogger("mptcpanalyzer")
       logger.setLevel(level=loglevel)
       # logging.basicConfig(level=loglevel)
       cls.cache_folder = tempfile.mkdtemp()
       # we are responsible for destroying it 
       # print("cls.cache_folder=", cls.cache_folder)


   @classmethod
   def tearDownClass(cls):
       # TODO unlink cls.cache_folder 
       # shutil.rmtree(cls.cache_folder)
       print("cache=%s" % cls.cache_folder)

   def setUp(self):
       """ Run before each test"""
       # todo use a tempdir as cache
       # config["cache"] = 
       # config = MpTcpAnalyzerConfig("")
       # config["mptcpanalyzer"]["cache"] = self.__class__.cache_folder
       # self.m = MpTcpAnalyzer(config)
       # self.assertEqual(self.m.cache.folder, self.cache_folder)
       # print("folder cache %s" % self.m.cache.folder)
       pass

   def create_z(self, config=None):

       config = MpTcpAnalyzerConfig("") if config is None else config
       config["mptcpanalyzer"]["cache"] = self.__class__.cache_folder
       z = MpTcpAnalyzer(config)
       self.assertEqual(z.cache.folder, self.cache_folder)
       print("folder cache %s" % z.cache.folder)
       return z


#    def setup_plot_mgr(self):
#        """
#        We have to load them manually

#        .. see: https://github.com/openstack/stevedore/blob/master/stevedore/tests/test_test_manager.py
#        """

#        z = self.create_z()
#        #name , entry point, plugin, obj
#        plots = [
#            Extension("attr", 'mptcpanalyzer.plots.dsn:PerSubflowTimeVsAttribute',
#            None, mp.plots.dsn.PerSubflowTimeVsAttribute())
#        ]
#        mgr = z.plot_manager.make_test_instance(plots)
#        z.plot_manager = mgr
#        # TODO now we need to use that !


#    def test_oneshot(self):
#        # TODO test when launched via subprocess
#        # - with a list of commands passed via stdin
#        cmd = " help"
#        # z = self.create_z()
#        oneshot(cmd)
#        # self.assertEqual(ret, 0)

#    @unittest.skip("todo + Not sure pcap are valid yet")
#    def test_mapping_connections(self):
#        """
#        Test to check if the program correctly mapped one connection to another
#        """
#        z = self.create_z()
#        ds1 = load_into_pandas("examples/node0.pcap")
#        ds2 = load_into_pandas("examples/node1.pcap")

   def test_plot_owd(self):
       # self.m.do_plot("plot owd 0")
       out_basename = "interarrival.png"
       # out_basename = "interarrival_with_title.png"
       tpl = "plot owd {client_pcap} {server_pcap} 0"
       cmd = tpl.format(
           client_pcap="examples/node0filtered.pcapng",
           server_pcap="examples/node1filtered.pcapng"
       )
       # owd_tcp --display examples/server_2.pcap examples/client_2.pcap 0 0
       # pd.DataFrame()
       # with tempfile.TemporaryDirectory() as tempdir:
       #     out_fullname = os.path.join(tempdir, out_basename)
       #     self.check_plot_output(cmd, out_fullname)


   def test_load_pcap(self):
       """
       Check that it can load a basic mptcp pcap, w/o regen
       check it takes into account the cache
       check it fails when file does not exist or is corrupted
       """
       # to test for errors
       # with self.assertRaises(ValueError):
       self.m.do_load_pcap("examples/iperf-mptcp-0-0.pcap --regen")



   # @unittest.skip("")
   def test_list_subflows(self):
       """
       Test that it can list subflows
       """
       z = self.create_z()
       # self.m.do_ls("0")
       # fails because the file is not loaded yet
       with self.assertRaises(mp.MpTcpException):
           z.onecmd("ls 0")

       z.onecmd("load " + mptcp_pcap)
       z.onecmd("ls 0")

#        # fails because there are no packets with this id
#        with self.assertRaises(mp.MpTcpException):
#            z.onecmd("ls 4")

#    def test_list_connections(self):
#        """
#        TODO should return different number
#        """
#        # fails because file not loaded
#        z = self.create_z()
#        self.assertRaises(mp.MpTcpException, z.do_lc, "")
#        z.onecmd("load " + mptcp_pcap)
#        z.onecmd("lc")
#        # oneshot("lc")

#    def test_list_plots_attr(self):
#        """
#        Check if properly list available plugins
#        """
#        #http://docs.openstack.org/developer/stevedore/managers.html#stevedore.extension.Extension
#        # plugin, obj
#        # setup_plot_mgr
#        z = self.create_z()
#        self.setup_plot_mgr()
#        plot_names = z.list_available_plots()
#        print("plot names=", plot_names)
#        self.assertIn("attr", plot_names)
#        # self.assertIn("", plot_names)
#        # for i in range():
#        #     with self.subTest(i=i):
#        #         self.assertIn()

#    def test_plot_interarrival(self):

#        # tpl = """ plot interarrival {pcap} dsn --out={out}"""
#        # z = self.create_z() 
#        out_basename = "interarrival.png"
#        # out_basename = "interarrival_with_title.png"
#        tpl = "plot interarrival {pcap} dsn"
#        cmd = tpl.format(pcap=mptcp_pcap)
#        with tempfile.TemporaryDirectory() as tempdir:
#            # with 
#            # io.StringIO(content)
#            # tpl.format(
#            #     pcap=mptcp_pcap,
#            #     os.path.exists(os.path.join(tempdir, "test1.png")))
#            # )
#            # tempdir = self.batch("tests/batch_interarrival.txt")
#            out_fullname = os.path.join(tempdir, out_basename)
#            self.check_plot_output(cmd, out_fullname)


#    def check_plot_output(self, cmd, out, ):
#        # if out:
#        #     cmd += " --out=%s" % out

#        # if title:
#        #     cmd += " --title='%s'" % title

#        self.assertFalse(os.path.exists(out), "command not run yet")
#        oneshot(cmd)
#        self.assertTrue(os.path.exists(out), "plot should have created it")
#        os.unlink(out)
#        oneshot(cmd + " --title='Successfully overriden title'")
#        self.assertTrue(os.path.exists(out), "plot should have created it")
#        os.unlink(out)
#        # TODO check_display flag here or ??
#        # oneshot(cmd + " --title='Successfully overriden title --display'")
#        # z.onecmd(tpl.format(
#        #     pcap=mptcp_pcap,
#        #     out=out_fullname,
#        #     title="--title='testing title overriding'"
#        # ))


#    # test_oneshot and check there is no SystemExit
#    def test_flag_batch(self):
#    # def batch(self, filename):
#        """
#        TODO add share_cachedir ??
#        Run several commands written in a file and make sure
#        some files are created

#        filename MUST be fullpath !
#        you have to clean it yourself
#        """
#        # f = Path(tmpdir, "toto.txt").touch()
#        filename = "tests/batch_commands.txt"
#        parent_dir = pathlib.Path(os.path.realpath(__file__)).parent
#        with tempfile.TemporaryDirectory() as tempdir:
#            # newfile = pathlib.Path(tempdir, filename)
#            # # newfile = os.path.join(tempdir, filename)
#            # print("Copy of %s to %s" % (filename, newfile))
#            # print("makedirs to %s" % newfile.parent)
#            # os.makedirs(newfile.parent.as_posix(), exist_ok=True)
#            # or do a symlink
#            # shutil.copytree("examples", tempdir)
#            os.symlink(os.path.join(parent_dir + "examples"), os.path.join(tempdir, "examples"))
#            os.chdir(tempdir)
#            # --load {f} 
#            # oneshot(" --batch ")
#            cmd = " --batch {cmd_file}".format(
#                # use sys.path
#                cmd_file=os.path.join(parent_dir, filename),
#            )
#            self.assertEqual(oneshot(cmd), 0, "An error happened")
#            # TODO check some files are created etc...
#            return tempdir

#    def test_flag_cachedir(self):
#        with tempfile.TemporaryDirectory() as tempdir:
#            self.assertEqual(len(os.listdir(tempdir)), 0, "new folder should be empty")
#            oneshot(" --cachedir={cache} --load={pcap} exit".format(cache=tempdir, pcap=mptcp_pcap))
#            self.assertGreaterEqual(len(os.listdir(tempdir)), 1, "new folder should have one file at least")
#            # tempdir.cleanup()


#    @unittest.skip("unfinished")
#    def test_flag_config(self):
#        """ 
#        check that config is loaded properly
#        """
#        with tempfile.TemporaryDirectory() as tempdir:

#            conf = os.path.join(tempdir, "config") 
#            shutil.copyfile(config_file, conf)
#            # Todo check a config value

#    def test_plot_attr_postloaded(self):
#        # self.setup_plot_mgr()
#        z = self.create_z()
#        with tempfile.TemporaryDirectory() as tempdir:
#            out = os.path.join(tempdir, "out.png")
#            print("out=", out)
#            oneshot("plot attr examples/iperf-mptcp-0-0.pcap 0 client dsn --out %s" % (out))
#            # TODO test that it exists
#            self.assertTrue(os.path.exists(out), "previous command should have created a plot")
#            # plot attr 0 Client dsn 
#            # plot attr 0 Client dsn  --title "custom title" --out test_with_title.png
#            # plot attr 0 Client dsn  --skip 1 --skip 3 --style examples/red_o.mplstyle --title "Test with matplotlib colors" --out test_title_style.png

#        # TODO test --title
#        # self.m.do_plot("attr examples/iperf-mptcp-0-0.pcap 0 client dsn")
#        # self.batch("tests/batch_commands.txt")

#    def test_list_plots_2(self):
#        z = self.create_z()
#        plot_names = z.list_available_plots()
#        print("plot names=", plot_names)
#        # self.assertIn("attr", plot_names)
#        # self.assertIn("", plot_names)


#    @unittest.skip("not upstreamed yet")
#    def testplot_ns3(self):
#        """
#        Not a good test, too involving
#        """

#        # self.m.do_plot("ns3 --meta examples/ cwnd 0")
