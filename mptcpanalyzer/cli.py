#!/usr/bin/env python3
# -*- coding: utf8
# PYTHON_ARGCOMPLETE_OK
# vim: set et fenc=utf-8 ff=unix sts=4 sw=4 ts=4 :

# Copyright 2015-2016 Université Pierre et Marie Curie
# author: Matthieu coudron , matthieu.coudron@lip6.fr
"""
# the PYTHON_ARGCOMPLETE_OK line a few lines up can enable shell completion
for argparse scripts as explained in
- http://dingevoninteresse.de/wpblog/?p=176
- https://travelingfrontiers.wordpress.com/2010/05/16/command-processing-argument-completion-in-python-cmd-module/

"""
import sys
import argparse
import logging
import os
import subprocess
# from mptcpanalyzer.plot import Plot
from mptcpanalyzer.tshark import TsharkExporter
from mptcpanalyzer.config import MpTcpAnalyzerConfig
# from mptcpanalyzer import get_default_fields, __default_fields__
from mptcpanalyzer.version import __version__
import mptcpanalyzer.connection as mc
import mptcpanalyzer as mp
import stevedore
# import mptcpanalyzer.config
import pandas as pd
# import matplotlib.pyplot as plt
import shlex
import cmd
import traceback
import pprint
import textwrap

from stevedore import extension

plugin_logger = logging.getLogger("stevedore")
plugin_logger.addHandler(logging.StreamHandler())

log = logging.getLogger("mptcpanalyzer")
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)
# handler = logging.FileHandler("mptcpanalyzer.log", delay=False)


def is_loaded(f):
    """
    Decorator checking that dataset has correct columns
    """
    def wrapped(self, *args):
        if self.data is not None:
            return f(self, *args)
        else:
            raise mp.MpTcpException("Please load a pcap with `load` first")
        return None
    return wrapped



# class InputFile: 

#     def __init__(self):
#         self.cache = 
#         self.filename
#         self.loaded_from_cache = False
#         self.dataframe


class MpTcpAnalyzer(cmd.Cmd):
    """
    mptcpanalyzer can run into 3 modes:

    #. interactive mode (default): an interpreter with some basic completion will accept your commands. There is also some help embedded.
    #. if a filename is passed as argument, it will load commands from this file
    #. otherwise, it will consider the unknow arguments as one command, the same that could be used interactively



    """

    intro = textwrap.dedent("""
        Press ? to list the available commands and `help <command>` or `<command> -h`
        for a detailed help of the command
        """.format(__version__))

    def stevedore_error_handler(manager, entrypoint, exception):
        print("Error while loading entrypoint [%s]" % entrypoint)

    def __init__(self, cfg: MpTcpAnalyzerConfig, stdin=sys.stdin):
        """

        Args:
            cfg (MpTcpAnalyzerConfig): A valid configuration


        Attributes:
            prompt (str): Prompt seen by the user, displays currently loaded pcpa
            config: configution to get user parameters
            data:  dataframe currently in use
        """
        self.prompt = "%s> " % "Ready"
        self.config = cfg
        self.data = None

        ### LOAD PLOTS
        ######################
        # you can  list available plots under the namespace
        # https://pypi.python.org/pypi/entry_point_inspector

        # mgr = driver.DriverManager(
        self.plot_mgr = extension.ExtensionManager(
            namespace='mptcpanalyzer.plots',
            invoke_on_load=True,
            verify_requirements=True,
            invoke_args=(),
        )

        self.cmd_mgr = extension.ExtensionManager(
            namespace='mptcpanalyzer.cmds',
            invoke_on_load=True,
            verify_requirements=True,
            invoke_args=(),
            propagate_map_exceptions=False,
            on_load_failure_callback=self.stevedore_error_handler
        )

        # if loading commands from a file, we disable prompt not to pollute
        # output
        if stdin != sys.stdin:
            log.info("Disabling prompt because reading from stdin")
            self.use_rawinput = False
            self.prompt = ""
            self.intro = ""

        """
        The optional arguments stdin and stdout specify the input and output file objects that the Cmd instance or subclass instance will use for input and output. If not specified, they will default to sys.stdin and sys.stdout.
        """
        super().__init__(completekey='tab', stdin=stdin)


    @property
    def plot_manager(self):
        return self.plot_mgr

    @plot_manager.setter
    def plot_manager(self, mgr):
        """
        Override the default plot manager, only used for testing
        :param mgr: a stevedore plugin manager
        """
        self.plot_mgr = mgr


    def load_plugins(self, mgr = None):
        """
        This function monkey patches the class to inject Command plugins

        :param mgr: override the default plugin manager when set.

        Useful to run tests
        """
        mgr = mgr if mgr is not None else self.cmd_mgr

        def _inject_cmd(ext, data):
            log.debug("Injecting plugin %s" % ext.name)
            for prefix in ["do", "help", "complete"]:
                method_name = prefix + "_" + ext.name
                try:
                    obj = getattr(ext.obj, prefix)
                    if obj:
                        setattr(MpTcpAnalyzer, method_name, obj)
                except AttributeError:
                    log.debug("Plugin does not provide %s" % method_name)

        # there is also map_method available
        try:
            mgr.map(_inject_cmd, self)
        except stevedore.exception.NoMatches as e:
            log.error("stevedore: No matches (%s)" % e)

    def precmd(self, line):
        """
        Here we can preprocess line, with for instance shlex.split() ?
        Note:
            This is only called when using cmdloop, not with onecmd !
        """
        # default behavior
        print(">>> %s" % line)
        return line

    def cmdloop(self, intro=None):
        """
        overrides baseclass just to be able to catch exceptions
        """
        try:
            super().cmdloop()
        except KeyboardInterrupt as e:
            pass

        # Exception raised by sys.exit(), which is called by argparse
        # we don't want the program to finish just when there is an input error
        except SystemExit as e:
        #     # e is the error code to call sys.exit() with
            # log.debug("Input error: " % e)
            # print("Error: %s"% e)
            self.cmdloop()
        # you can set a tuple of exceptions
        except mp.MpTcpException as e:
            print(e)
            self.cmdloop()
        except Exception as e:
            log.critical("Unknown error, aborting...")
            log.critical(e)
            print("Displaying backtrace:\n")
            print(traceback.print_exc())

        # finally:
        #     log.debug("Error logged")
        # except NotImplementedError:
        #     print("Plot subclass miss a requested feature")
        #     return 1

    def postcmd(self, stop, line):
        """
        Override baseclass
        returning true will stop the program
        """
        log.debug("postcmd result for line [%s] => %r", line, stop)

        return True if stop == True else False


    def require_fields(mandatory_fields: list):  # -> Callable[...]:
        """
        Decorator used to check dataset contains all fields required by function
        """

        def check_fields(self, *args, **kwargs):
            columns = list(self.data.columns)
            for field in mandatory_fields:
                if field not in columns:
                    raise Exception(
                        "Missing mandatory field [%s] in csv, regen the file or check the separator" % field)
        return check_fields

    # @require_fields(['sport', 'dport', 'ipdst', 'ipsrc'])
    @is_loaded
    def do_ls(self, args):
        """
        list mptcp subflows
                [mptcp.stream id]

        Example:
            ls 0
        """
        parser = argparse.ArgumentParser(
            description="List subflows of an MPTCP connection"
        )

        parser.add_argument("mptcpstream", action="store", type=int,
            help="Equivalent to wireshark mptcp.stream id"
        )

        args = parser.parse_args (shlex.split(args))
        self.list_subflows(args.mptcpstream)

    @is_loaded
    def list_subflows(self, mptcpstreamid : int):
        con = mc.MpTcpConnection.build_from_dataframe(self.data, mptcpstreamid)
        print("Description of mptcp.stream %d " % mptcpstreamid)
        print(con)

        print("The connection has %d subflow(s) (client/server): " % (len(con.subflows)))
        for sf in con.subflows:
            print ("\t%s" % sf)

    def help_ls(self):

        return "Use parser -h"

    def complete_ls(self, text, line, begidx, endidx):
        """ help to complete the args """
        # conversion to set removes duplicate keys
        l = list(set(self.data["mptcpstream"]))
        # convert items to str else it won't be used for completion
        l = [str(x) for x in l]

        return l


    @is_loaded
    def do_summary(self, line):
        """
        Summarize contributions of each subflow
        For now it is naive, does not look at retransmissions ?
        """
        parser = argparse.ArgumentParser(
                description="Prints a summary of the mptcp connection"
        )
        parser.add_argument("mptcpstream", type=int, help="mptcp.stream id")
        parser.add_argument("--deep", action="store_true", help="Deep analysis, computes transferred bytes etc...")
        parser.add_argument("--amount", action="store_true", type=int, help="mptcp.stream id")
        # try:
        #     mptcpstream = int(mptcpstream)
        # except ValueError as e:
        #     print("Expecting the mptcp.stream id as argument: %s" % e)
        #     return

        args = parser.parse_args(line)
        df = self.data[self.data.mptcpstream == args.mptcpstream]
        if df.empty:
            print("No packet with mptcp.stream == %d" % args.mptcpstream)

        # for instance
        dsn_min = df.dss_dsn.min()
        dsn_max = df.dss_dsn.max()
        total_transferred = dsn_max - dsn_min
        d = df.groupby('tcpstream')
        # drop_duplicates(subset='rownum', take_last=True)
        print("mptcpstream %d transferred %d" % (mptcpstream, total_transferred))
        for tcpstream, group in d:
            subflow_load = group.drop_duplicates(
                subset="dss_dsn").dss_length.sum()
            print(subflow_load)
            print('tcpstream %d transferred %d out of %d, hence is responsible for %f%%' % (
                tcpstream, subflow_load, total_transferred, subflow_load / total_transferred * 100))

    @is_loaded
    def do_lc(self, *args):
        """
        List mptcp connections via their ids (mptcp.stream)
        """
        # self.data.describe()
        streams = self.data.groupby("mptcpstream")

        print('%d mptcp connection(s)' % len(streams))
        for mptcpstream, group in streams:
            self.list_subflows(mptcpstream)


    def do_load(self, args):
        """
        Load the file as the current one
        """
        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots'
        )
        parser.add_argument("input_file", action="store",
                help="Either a pcap or a csv file (in good format)."
                "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
                "If it can't find one (or with the flag --regen), it will generate a "
                "csv from the pcap with the external tshark program."
                )
        parser.add_argument("--regen", "-r", action="store_true",
                help="Force the regeneration of the cached CSV file from the pcap input")

        args = parser.parse_args(shlex.split(args))

        self.data = self.load_into_pandas(args.input_file, args.regen)
        self.prompt = "%s> " % os.path.basename(args.input_file,)

    def do_plot(self, args, mgr=None):
        """
        Plot DSN vs time
        """
        self.plot_mptcpstream(args)

    def help_plot(self):
        print("Run plot -h")

    def complete_plot(self, text, line, begidx, endidx):
        # types = self._get_available_plots()
        # print("Line=%s" % line)
        # print("text=%s" % text)
        # print(types)
        l = [x for x in types if x.startswith(text)]
        return l


    def do_list_available_plots(self, args):
        """
        Print available plots. Mostly for debug, you should use 'plot'.
        """

        plot_names = self.list_available_plots()
        print(plot_names)

    def list_available_plots(self):
        # def _get_names(ext, names: list):
        #     names.append (ext.name)

        # names = []
        # self.plot_mgr.map(_get_names, names)
        # def _get_names(ext, names: list):
        #     names.append (ext.name)

        # self.plot_mgr.map(_get_names, names)
        # return names
        return self.plot_mgr.names()

# TODO rename look intocache ?
    def get_matching_csv_filename(self, filename, force_regen : bool):
        """
        Name is bad, since the function can generate  the file if required
        Expects a realpath as filename
        Accept either a .csv or a .pcap file
        Returns realpath towards resulting csv filename
        """
        realpath = filename
        basename, ext = os.path.splitext(realpath)
        # print("Basename=%s" % basename)
        # csv_filename = filename

        if ext == ".csv":
            log.debug("Filename already has a .csv extension")
            csv_filename = realpath
        else:
            print("%s format is not supported as is. Needs to be converted first" %
                (filename))

            def matching_cache_filename(filename):
                """
                Expects a realpath else
                """
                # create a list of path elements (separated by system separator '/' or '\'
                # from the absolute filename
                l = os.path.realpath(filename).split(os.path.sep)
                res = os.path.join(self.config["DEFAULT"]["cache"], '%'.join(l))
                _, ext = os.path.splitext(filename)
                if ext != ".csv":
                    res += ".csv"
                return res

            # csv_filename = filename + ".csv"  #  str(Filetype.csv.value)
            csv_filename = matching_cache_filename(realpath)
            cache_is_invalid = True

            log.debug("Checking for %s" % csv_filename)
            if os.path.isfile(csv_filename):
                log.info("A cache %s was found" % csv_filename)
                ctime_cached = os.path.getctime(csv_filename)
                ctime_pcap = os.path.getctime(filename)
                # print(ctime_cached , " vs ", ctime_pcap)

                if ctime_cached > ctime_pcap:
                    log.debug("Cache seems valid")
                    cache_is_invalid = False
                else:
                    log.debug("Cache seems outdated")


            # if matching csv does not exist yet or if generation forced
            if force_regen or cache_is_invalid:

                # recursively create the directories
                log.debug("Creating cache directory [%s]" % self.config["DEFAULT"]["cache"])
                os.makedirs(self.config["DEFAULT"]["cache"], exist_ok=True)

                log.info("Preparing to convert %s into %s" %
                        (filename, csv_filename))

                exporter = TsharkExporter(
                        self.config["DEFAULT"]["tshark_binary"],
                        self.config["DEFAULT"]["delimiter"],
                        self.config["DEFAULT"]["wireshark_profile"],
                )

                retcode, stderr = exporter.export_to_csv(
                        filename,
                        csv_filename,
                        mp.get_fields("fullname", "name"),
                        tshark_filter="mptcp and not icmp"
                )
                log.info("exporter exited with code=", retcode)
                if retcode:
                    raise Exception(stderr)
        return csv_filename

    def load_into_pandas(self, input_file, regen: bool =False):
        """
        intput_file can be filename or fd
        load csv mptpcp data into panda
        :param regen Ignore the cache and regenerate any cached csv file from the input pcap

        Returns:
            a panda.DataFrame
        """
        log.debug("Asked to load %s" % input_file)

        filename = os.path.expanduser(input_file)
        filename = os.path.realpath(filename)
        csv_filename = self.get_matching_csv_filename(filename, regen)

        temp = mp.get_fields("fullname", "type")
        dtypes = {k: v for k, v in temp.items() if v is not None}
        log.debug("Loading a csv file %s" % csv_filename)

        data = pd.read_csv(csv_filename, sep=self.config["DEFAULT"]["delimiter"],
            dtype=dtypes,
            converters={
                "tcp.flags": lambda x: int(x, 16),
            }
        )

        data.rename(inplace=True, columns=mp.get_fields("fullname", "name"))

        # pp = pprint.PrettyPrinter(indent=4)
        # log.debug("Dtypes after load:%s\n" % pp.pformat(data.dtypes))
        return data


    def plot_mptcpstream(self, cli_args, ):
        """
        global member used by others do_plot members *
        Loads required dataframes when necessary
        """

        parser = argparse.ArgumentParser(
            description='Generate MPTCP stats & plots')

        # TODO if no df loaded, add an argument ? or the plot should
        # say how many it needs?
        # if self.data is None:
        #     parser.add_argument()

        subparsers = parser.add_subparsers(
            dest="plot_type", title="Subparsers", help='sub-command help', )
        subparsers.required = True

        def register_plots(ext, subparsers):
            """Adds a parser per plot"""
            # check if dat is loaded
            parser = ext.obj.default_parser(self.data is not None)
            assert parser, "Forgot to return parser"
            subparsers.add_parser(ext.name, parents=[
                 parser   
                ],
                add_help=False
            )

        self.plot_mgr.map(register_plots, subparsers)

        # results = mgr.map(_get_plot_names, "toto")
        # for name, subplot in plot_types.items():
            # subparsers.add_parser(
                # name, parents=[subplot.default_parser()], add_help=False)

        # try:
        cli_args = shlex.split(cli_args)
        args, unknown_args = parser.parse_known_args(cli_args)
        # TODO generic filter
        plotter = self.plot_mgr[args.plot_type].obj

        dataframes = []
        if self.data is not None:
            dataframes.append(self.data)

        for pcap in getattr(args, "pcap", []):
            df = self.load_into_pandas(pcap)
            dataframes.append(df)


        dargs = vars(args) # 'converts' the namespace to a dict

        # TODO
        # inspect.getfullargspec(fileinput.input))
            # dataframes = [ plotter.preprocess(df, **dargs) for df in dataframes]
        result = plotter.run(dataframes, **dargs)
        plotter.postprocess(result, **dargs)

        # except SystemExit as e:
        #     # e is the error code to call sys.exit() with
        #     print("Parser failure:", e)
        # except NotImplementedError:
        #     print("Plot subclass miss a requested feature")
        #     return 1

    def do_clean_cache(self, line):
        """
        mptcpanalyzer saves pcap to csv converted files in a cache folder, (most likely
        $XDG_CACHE_HOME/mptcpanalyzer). This commands clears the cache.
        """
        # 
        print("Cleaning cache [%s]" % self.config.cache)
        for cached_csv in os.scandir(self.config.cache):
            log.info("Removing " + cached_csv.path)
            os.unlink(cached_csv.path)


    # def help_clean_cache(self):

    def do_dump(self, args):
        """
        Dumps content of the csv file, with columns selected by the user.
        Mostly used for debug
        """
        parser = argparse.ArgumentParser(description="dumps csv content")
        parser.add_argument('columns', default=[
                            "ipsrc", "ipdst"], choices=self.data.columns, nargs="*")

        parser.add_argument('-n', default=10, action="store",
                help="Number of results to display")
        args = parser.parse_args(shlex.split(args))
        print(self.data[args.columns])

    def complete_dump(self, text, line, begidx, endidx):
        """
        Should return a list of possibilities
        """
        l = [x for x in self.data.columns if x.startswith(text)]
        return l

    def do_quit(self, *args):
        """
        Quit/exit program
        """
        return True

    def do_EOF(self, line):
        """
        Keep it to be able to exit with CTRL+D
        """
        return True

    def preloop(self):
        """
        Executed once when cmdloop is called
        """
        super().preloop()
        # print("toto")




def main(arguments=None):
    """
    This is the entry point of the program

    Args:
        arguments_to_parse (list parsable by argparse.parse_args.): Made as a parameter since it makes testing easier


    Returns:
        return value will be passed to sys.exit
    """

    if not arguments:
        arguments = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description='Generate MPTCP (Multipath Transmission Control Protocol) stats & plots'
    )

    #  todo make it optional
    parser.add_argument(
            "--load","-l", dest="input_file",
            # type=argparse
            # "input_file",  nargs="?",
            # action="store", default=None,
            help="Either a pcap or a csv file (in good format)."
            "When a pcap is passed, mptcpanalyzer will look for a its cached csv."
            "If it can't find one (or with the flag --regen), it will generate a "
            "csv from the pcap with the external tshark program."
            )
    parser.add_argument('--version', action='version', version="%s" % (__version__))
    parser.add_argument("--config", "-c", action="store",
            help="Path towards the config file. If not set, mptcpanalyzer will try"
                " to load first $XDG_CONFIG_HOME/mptcpanalyzer/config and then "
                " $HOME/.config/mptcpanalyzer/config"
    )
    parser.add_argument("--debug", "-d", action="count", default=0,
            help="More verbose output, can be repeated to be even more "
                " verbose such as '-dddd'"
    )
    parser.add_argument("--regen", "-r", action="store_true",
            help="mptcpanalyzer creates a cache of files in the folder "
                "$XDG_CACHE_HOME/mptcpanalyzer or $HOME/.config/mptcpanalyzer"
            "Force the regeneration of the cached CSV file from the pcap input"
    )
    parser.add_argument("--batch", "-b", action="store", type=argparse.FileType('r'),
            default=None,
            help="Accepts a filename as argument from which commands will be loaded."
            "Commands follow the same syntax as in the interpreter"
            "can also be used as "
    )


    args, unknown_args = parser.parse_known_args(arguments)
    cfg = MpTcpAnalyzerConfig(args.config)

    # logging.CRITICAL = 50
    level = logging.CRITICAL - min(args.debug, 4) * 10
    log.setLevel(level)
    print("Log level set to %s " % logging.getLevelName(level))


    try:

        analyzer = MpTcpAnalyzer(cfg, )

        if args.input_file:
            log.info("Input file")
            cmd = args.input_file
            cmd += " -r" if args.regen else ""
            analyzer.do_load ( cmd )
            # analyzer.onecmd(cmd)
        
        if args.batch:
            log.info("Batched commands")
            # with open(args.batch) as fd:
            for command in args.batch:
                log.info(">>> %s" % command)
                analyzer.onecmd(command)

        # if extra parameters passed via the cmd line, consider it is one command
        # not args.batch ? both should conflict
        elif unknown_args:
            log.info("One-shot command with unknown_args=  %s" % unknown_args)

            # list2cmdline is undocumented function so it  might disappear
            # http://stackoverflow.com/questions/12130163/how-to-get-resulting-subprocess-command-string
            # but just doing "analyzer.onecmd(' '.join(unknown_args))" is not enough
            analyzer.onecmd(subprocess.list2cmdline(unknown_args))
        else:
            log.info("Starting interactive mode")
            analyzer.cmdloop()

    except Exception as e:
        print("An error happened :\n%s" % e)
        print("Displaying backtrace:\n")
        print(traceback.print_exc())
        return 1
    finally:
        return 0


if __name__ == '__main__':
    main()
