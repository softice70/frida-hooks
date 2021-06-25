#! /usr/bin/python
# -*-coding: UTF-8 -*-

import platform
import configparser
import os
from os.path import abspath, dirname
from optparse import OptionGroup
import frida
from frida_hooks.scriptor import Scriptor
from frida_hooks.utils import *
import hashlib


md5 = lambda bs: hashlib.md5(bs).hexdigest()


class FridaAgent:
    _frida_server_path = '/data/local/tmp/frida-server'
    def __init__(self, parser):
        self._parser = parser
        self._device = None
        self._session = None
        self._script = None
        self._app_package = None
        self._scripts_map = {}
        self._is_app_suspend = False
        self._target_pid = -1
        self._keep_running = False
        self._init_parser(self._parser)
        self._enable_deep_search_for_dump_dex = False
        self._imp_mods = {}
        pass

    @staticmethod
    def start_frida_server():
        name = re.split('/', FridaAgent._frida_server_path)[-1]
        frida_server_pid = get_pid_by_adb_shell(FridaAgent._frida_server_path)
        if frida_server_pid > 0:
            print(f'{name}[pid:{frida_server_pid}] is already running...')
            return frida_server_pid
        else:
            FridaAgent.__start_frida_server()
            sid = get_pid_by_adb_shell(FridaAgent._frida_server_path, 10)
            if sid < 0:
                print("error: frida server %s failed to start" % FridaAgent._frida_server_path)
            else:
                print(f'{FridaAgent._frida_server_path}[pid:{sid}] is running...')
            return sid

    @staticmethod
    def stop_frida_server():
        name = re.split('/', FridaAgent._frida_server_path)[-1]
        frida_server_pid = get_pid_by_adb_shell(FridaAgent._frida_server_path)
        if frida_server_pid < 0:
            print(f'{name} is not running')
        else:
            cmd = "adb shell su -c 'kill -9 %d'" % frida_server_pid
            exec_cmd(cmd, 10)
            print(f'{name}[pid:{frida_server_pid}] is stop')

    @staticmethod
    def show_frida_server_status(wait_time_in_sec=1):
        name = re.split('/', FridaAgent._frida_server_path)[-1]
        frida_server_pid = get_pid_by_adb_shell(FridaAgent._frida_server_path, wait_time_in_sec)
        if frida_server_pid < 0:
            print(f'{name} is not running')
        else:
            print(f'{name}[pid:{frida_server_pid}] is running...')

    def list_app(self, check_frida_server=True):
        if not check_frida_server or FridaAgent.start_frida_server() > 0:
            app_list = self._device.enumerate_applications()
            app_list.sort(key=lambda s: s.identifier)
            for item in app_list:
                print(
                    f'{item.pid}\t{Colors.keyword3}{item.identifier}{" " * (60 - len(item.identifier))}{Colors.keyword}{item.name}{Colors.reset}')
        else:
            raise Exception()

    def list_process(self, check_frida_server=True):
        if not check_frida_server or FridaAgent.start_frida_server() > 0:
            app_list = self._device.enumerate_applications()
            app_dict = {}
            for app in app_list:
                app_dict[app.identifier] = app.name
            proc_list = self._device.enumerate_processes()
            proc_list.sort(key=lambda s: s.name)
            for item in proc_list:
                cn_name = app_dict[item.name] if item.name in app_dict.keys() else ''
                print(f'{item.pid}\t{Colors.keyword3}{item.name}{" " * (60 - len(item.name))}{Colors.keyword}{cn_name}{Colors.reset}')
        else:
            raise Exception()

    def run(self):
        try:
            (options, args) = self._parser.parse_args()
            if options.monochrome:
                Colors.set_monochrome_mode()
            self._init_device()
            if len(args) == 0 and not options.config:
                self._exec_internal_cmd(options)
            elif len(args) > 1:
                self._parser.print_help()
            else:
                if options.config:
                    self._load_config(options.config)
                else:
                    self._app_package = args[0]
                    self._load_options(options)
                self._keep_running = self._start_app(is_suspend=options.is_suspend)
                while self._keep_running:
                    if not self._load_script():
                        self.print_internal_cmd_help()
                    self._run_console()
                    self._unload_script()
        except Exception as e:
            print(e)
        self.exit()

    def exit(self):
        if self._session:
            self._session.detach()
        print(Colors.exit + 'frida hooker exited.' + Colors.reset)

    def _load_config(self, cfg_file):
        ret = False
        try:
            cf = configparser.ConfigParser()
            cf.read(cfg_file, 'utf-8')
            app_package = cf.get("main", "app_package")
            log_file = cf.get("main", "log_file") if cf.has_option("main", "log_file") else ''
            Scriptor.set_silence((cf.get("main", "silence").lower() == 'true') if cf.has_option("main", "silence") else False)
            Scriptor.set_show_detail((cf.get("main", "show_detail").lower() == 'true') if cf.has_option("main", "show_detail") else False)
            Scriptor.reset_frida_cmds()
            init_logger(log_file)
            if not self._app_package or self._app_package == app_package:
                self._app_package = app_package
                Scriptor.set_app_package(self._app_package)
                configs = re.split(',', cf.get("main", "load_configs"))
                for item in configs:
                    script = Scriptor.prepare_script({'cf': cf, 'section': item}, self._imp_mods)
                    if script:
                        self._scripts_map[script['key']] = script
                        ret = True
                print(f'{Colors.keyword2}{cfg_file}{Colors.reset} is loaded...')
            else:
                print(
                    f'{Colors.warning} warning: invalidate app_package:[{Colors.keyword3}{app_package}{Colors.warning}] in the config:[{Colors.keyword3}{cfg_file}{Colors.warning}]{Colors.reset}')
        except Exception as e:
            print(e)
        finally:
            return ret

    def _load_options(self, options):
        Scriptor.set_silence(options.silence)
        Scriptor.set_show_detail(options.show_detail)
        Scriptor.set_app_package(self._app_package)
        script = Scriptor.prepare_script(options, self._imp_mods)
        if script:
            self._scripts_map[script['key']] = script
        init_logger(options.log_file)
        return self._scripts_map

    def _get_pid(self, name, wait_time_in_sec=1):
        for i in range(wait_time_in_sec):
            try:
                proc_list = self._device.enumerate_processes()
                for proc in proc_list:
                    if proc.name == name:
                        return proc.pid
            except Exception as e:
                print(e)
                return -1
            time.sleep(1)
        return -1

    def _start_app_by_package_name(self, package, is_suspend=False):
        print(f'{package} is starting...')
        retry_times = 5
        for i in range(retry_times):
            self._target_pid = self._device.spawn(package)
            time.sleep(i)
            self._is_app_suspend = True
            if self._target_pid < 0:
                print("error: %s failed to start" % package)
                break
            else:
                print(f'{package}[pid:{self._target_pid}] is running...')
                if not is_suspend:
                    self._device.resume(self._target_pid)
                    self._is_app_suspend = False
                if self._attach_app():
                    break
        return self._target_pid

    def _attach_app(self):
        if self._target_pid > 0:
            if self._session:
                self._session.detach()
            try:
                self._session = self._device.attach(self._target_pid)
                self._script = None
                return True
            except Exception as e:
                print(e)
                pass
        self._target_pid = -1
        return False

    def _start_app(self, is_suspend=False):
        if self.start_frida_server() > 0:
            if not is_suspend:
                self._target_pid = self._get_proecess_id(self._app_package)
                if self._target_pid > 0:
                    self._attach_app()
                    print(f'{self._app_package}[pid:{self._target_pid}] is already running...')
            if self._target_pid <= 0:
                self._target_pid = self._start_app_by_package_name(self._app_package, is_suspend)
        return self._target_pid > 0

    def _is_app_running(self):
        pid = self._get_proecess_id(self._app_package)
        ret = (pid == self._target_pid)
        self._target_pid = pid
        return ret

    def _exec_cmd_disable_and_enable(self, cmd, isEnable):
        ret = False
        if len(cmd) == 2:
            if cmd[1] not in self._scripts_map.keys():
                print(f'key:{Colors.keyword2}{cmd[1]}{Colors.reset} not found')
            else:
                if self._scripts_map[cmd[1]]['isEnable'] != isEnable:
                    self._scripts_map[cmd[1]]['isEnable'] = isEnable
                    ret = True
                else:
                    print(
                        f'key:{Colors.keyword3}{cmd[1]}{Colors.reset} has already been set to {Colors.keyword2}{isEnable}{Colors.reset}')
        else:
            self.print_internal_cmd_help()
        return ret

    def _exec_cmd_remove_hook_item(self, cmd):
        ret = False
        if len(cmd) == 2:
            if cmd[1] not in self._scripts_map.keys():
                print(f'key:{Colors.keyword2}{cmd[1]}{Colors.reset} not found')
            else:
                del self._scripts_map[cmd[1]]
                ret = True
        else:
            self.print_internal_cmd_help()
        return ret

    @staticmethod
    def __start_frida_server():
        def kill_process():
            try:
                p.kill()
            except OSError:
                pass  # Swallow the error

        print(f'{FridaAgent._frida_server_path} is starting...')
        cmd = "adb shell su"
        sub_cmd = FridaAgent._frida_server_path + " &\n"
        p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(sub_cmd.encode())
        timer = Timer(3, kill_process)
        timer.start()
        p.wait()
        timer.cancel()

    def _load_script(self, wait_time_in_sec=10):
        scripts_str, fun_on_msg = Scriptor.gen_script_str(self._scripts_map)
        self._script = None
        ret = False
        self._script = self._session.create_script(scripts_str)
        self._script.on("message", fun_on_msg)
        for i in range(wait_time_in_sec):
            try:
                self._script.load()
                if self._is_app_suspend:
                    self._device.resume(self._target_pid)
                    self._is_app_suspend = False
                ret = True
                break
            except Exception as e:
                time.sleep(1)
                pass
        self._exec_script_cmd_after_load()
        self._scripts_map = Scriptor.clean_scripts_map(self._scripts_map)

        return ret

    def _unload_script(self):
        if self._script and self._session:
            self._script.unload()

    def _exec_script_cmd_after_load(self):
        for key in self._scripts_map.keys():
            self._exec_one_script(self._scripts_map[key])

    def _exec_one_script(self, script):
        if script['isEnable']:
            if script['cmd'] == 'dump_dex':
                self._dump_dex()
            elif script['cmd'] == 'dump_so':
                self._dump_so(script)
            elif script['cmd'] == 'list_app':
                self.list_app()
            elif script['cmd'] == 'list_process':
                self.list_process()
            elif script['api_cmd'] != '':
                eval(script['api_cmd'])

    @staticmethod
    def _print_internal_cmd_help():
        help_strs = [
            f'Usage: cmd [option]\ncmd:',
            f'\n  {Colors.keyword}h{Colors.keyword3}elp{Colors.reset}\t\tshow this help message',
            f'\n  {Colors.keyword}o{Colors.keyword3}ptions{Colors.reset}\tprint options',
            f'\n  {Colors.keyword}l{Colors.keyword3}ist{Colors.reset}\t\tshow hook list',
            f'\n  {Colors.keyword}c{Colors.keyword3}onfig <file>{Colors.reset}\tload the config file',
            f'\n  {Colors.keyword}d{Colors.keyword3}isable <key>{Colors.reset}\tset disable the hook item by key',
            f'\n  {Colors.keyword}e{Colors.keyword3}nable <key>{Colors.reset}\tset enable the hook item by key',
            f'\n  {Colors.keyword3}re{Colors.keyword}m{Colors.keyword3}ove <key>{Colors.reset}\tremove the hook item by key',
            f'\n  {Colors.keyword}r{Colors.keyword3}un [options]{Colors.reset}\trun hook option, see also <{Colors.keyword3}options{Colors.reset}>',
            f'\n       example: --hook_class --class com.xxx.xxx.xxxxxx.Classxxx',
            f'\n                --hook_func --class com.xxx.xxx.xxxxxx.Classxxx --func Funcxxx',
            f'\n                --hook_so_func --module libxxx.so --func getSign',
            f'\n                --hook_so_func --module libxxx.so --addr 0xedxxxxxx',
            f'\n  {Colors.keyword3}re{Colors.keyword}s{Colors.keyword3}tart{Colors.reset}\trestart the hook session',
            f'\n  {Colors.keyword3}cls{Colors.reset}\t\tclear screen',
            f'\n  {Colors.keyword}q{Colors.keyword3}uit{Colors.reset}\t\tquit'
        ]
        print("".join(help_strs))

    def _run_console(self):
        while self._keep_running:
            print_prompt()
            cmd = self._parse_internal_cmd(sys.stdin.readline().strip())
            if self._keep_running:
                if len(cmd) == 0 or cmd[0] == 'help' or cmd[0] == 'h':
                    self._print_internal_cmd_help()
                elif cmd[0] == 'list' or cmd[0] == 'l':
                    self._print_hook_info(self._scripts_map)
                elif cmd[0] == 'options' or cmd[0] == 'o':
                    Scriptor.print_cmds_help()
                elif cmd[0] == 'quit' or cmd[0] == 'q':
                    self._keep_running = False
                elif cmd[0] == 'config' or cmd[0] == 'c':
                    if self._exec_load_config(cmd):
                        break
                elif cmd[0] == 'disable' or cmd[0] == 'd':
                    if self._exec_cmd_disable_and_enable(cmd, False):
                        break
                elif cmd[0] == 'enable' or cmd[0] == 'e':
                    if self._exec_cmd_disable_and_enable(cmd, True):
                        break
                elif cmd[0] == 'remove' or cmd[0] == 'm':
                    if self._exec_cmd_remove_hook_item(cmd):
                        break
                elif cmd[0] == 'restart' or cmd[0] == 's':
                    break
                elif cmd[0] == 'cls':
                    os.system('clear')
                elif cmd[0] == 'run' or cmd[0] == 'r':
                    self._exec_cmd_run(cmd)
                else:
                    self._print_internal_cmd_help()

        if self._keep_running and not self._is_app_running():
            self._keep_running = self._attach_app()
            if not self._keep_running:
                self._keep_running = self._start_app_by_package_name(self._app_package) > 0

    def _exec_load_config(self, cmd):
        ret = False
        if len(cmd) == 2:
            ret = self._load_config(cmd[1])
        else:
            self._print_internal_cmd_help()
        return ret

    def _exec_cmd_run(self, cmd):
        if len(cmd) >= 2:
            script = Scriptor.prepare_script(cmd, self._imp_mods)
            if script and script['key'] not in self._scripts_map.keys():
                self._exec_one_script(script)
                if script['persistent']:
                    self._scripts_map[script['key']] = script
        else:
            self._print_internal_cmd_help()

    def _init_device(self):
        self._device = frida.get_usb_device(timeout=15)

    def _exec_internal_cmd(self, options):
        if options.start_server:
            self.start_frida_server()
        elif options.stop_server:
            self.stop_frida_server()
        elif options.status_server:
            self.show_frida_server_status()
        elif options.list_app:
            self.list_app(check_frida_server=False)
        elif options.list_process:
            self.list_process(check_frida_server=False)
        else:
            self._parser.print_help()

    @staticmethod
    def _parse_internal_cmd(cmd_str):
        cmds_orig = re.split(' ', cmd_str)
        cmd = []
        for item in cmds_orig:
            if len(item) > 0:
                cmd.append(item)
        return cmd

    @staticmethod
    def _print_hook_info(scripts_map):
        for key in scripts_map.keys():
            if scripts_map[key]['isEnable']:
                print(f'[{Colors.title}✓{Colors.reset}] {Colors.keyword}{key}{Colors.reset}')
            else:
                print(f'[{Colors.title}✗{Colors.reset}] {key}')

    def _get_proecess_id(self, app):
        pid = -1
        try:
            app_proc = self._device.get_process(app)
            pid = app_proc.pid
        except Exception:
            pass
        return pid

    def _dump_so(self, script):
        module_name = script['params']['module']
        info = self._script.exports.find_so(module_name)
        if info:
            try:
                bs = self._script.exports.memory_dump(info['base'], info['size'])
                app_path = f'./{self._app_package}/'
                if not os.path.exists(app_path):
                    os.mkdir(app_path)
                tmp_so_path = f'{self._app_package}/{module_name}.tmp'
                with open(tmp_so_path, 'wb') as out:
                    out.write(bs)
                fixed_so_path = f'{self._app_package}/{module_name}'
                if self._so_fix(tmp_so_path, fixed_so_path, info['base']):
                    os.remove(tmp_so_path)
                else:
                    os.rename(tmp_so_path, fixed_so_path)
                print(
                    f"{Colors.title}[DumpSo]: Base={info['base']}, Size={hex(info['size'])}, SavePath={Colors.path}{os.getcwd()}/{fixed_so_path}{Colors.reset}")
            except Exception as e:
                print(f"{Colors.warning}[Except] - {e}: {info}{Colors.reset}")
            print_screen(f'{Colors.title}{module_name} dump finished!{Colors.reset}')

    @staticmethod
    def _so_fix(source, output, base):
        if platform.system().lower() == 'windows':
            fixer_file = os.path.join(dirname(abspath(__file__)), 'bin\\SoFixer-Windows-64.exe')
            cmd = f'{fixer_file} -m {base} -s {source} -o {output}'
            ret = exec_cmd(cmd, 20)
            print_screen(ret, is_show_prompt=False)
            return True
        else:
            return False

    def _dump_dex(self):
        if self._enable_deep_search_for_dump_dex:
            print(f"{Colors.keyword}[DEXDump]: deep search mode is enable, maybe wait long time.{Colors.reset}")

        mds = []
        print(f'{Colors.title}scanning dex in memory...{Colors.reset}')
        matches = self._script.exports.scan_dex(self._enable_deep_search_for_dump_dex)
        for info in matches:
            try:
                bs = self._script.exports.memory_dump(info['addr'], info['size'])
                md = md5(bs)
                if md in mds:
                    print(f"{Colors.keyword}[DEXDump]: Skip duplicate dex {info['addr']}<{md}>{Colors.reset}")
                    continue
                mds.append(md)
                if not os.path.exists("./" + self._app_package + "/"):
                    os.mkdir("./" + self._app_package + "/")
                bs = self._dex_fix(bs)
                with open(self._app_package + "/" + info['addr'] + ".dex", 'wb') as out:
                    out.write(bs)
                print(
                    f"{Colors.title}[DEXDump]: DexSize={hex(info['size'])}, DexMd5={md}, SavePath={Colors.path}{os.getcwd()}/{self._app_package}/{info['addr']}.dex{Colors.reset}")
            except Exception as e:
                print(f"{Colors.warning}[Except] - {e}: {info}{Colors.reset}")
        print_screen(f'{Colors.title}Dex dump finished!{Colors.reset}')

    @staticmethod
    def _dex_fix(dex_bytes):
        import struct
        dex_size = len(dex_bytes)

        if dex_bytes[:4] != b"dex\n":
            dex_bytes = b"dex\n035\x00" + dex_bytes[8:]

        if dex_size >= 0x24:
            dex_bytes = dex_bytes[:0x20] + struct.Struct("<I").pack(dex_size) + dex_bytes[0x24:]

        if dex_size >= 0x28:
            dex_bytes = dex_bytes[:0x24] + struct.Struct("<I").pack(0x70) + dex_bytes[0x28:]

        if dex_size >= 0x2C and dex_bytes[0x28:0x2C] not in [b'\x78\x56\x34\x12', b'\x12\x34\x56\x78']:
            dex_bytes = dex_bytes[:0x28] + b'\x78\x56\x34\x12' + dex_bytes[0x2C:]

        return dex_bytes

    @staticmethod
    def _init_parser(parser):
        Scriptor.add_cmd_options(parser)
        Scriptor.add_param_options(parser)

        running_group = OptionGroup(parser, 'Running Options')
        running_group.add_option("-S", "--spawn", action="store_true", dest="is_suspend", default=False,
                          help='spawn mode of Frida, that suspend app during startup')
        running_group.add_option("-m", "--monochrome", action="store_true", dest="monochrome", default=False,
                          help='Set to monochrome mode')
        running_group.add_option("", "--silence", action="store_true", dest="silence", default=False,
                          help='no message is output to screen')
        running_group.add_option("-d", "--show_detail", action="store_true", dest="show_detail", default=False,
                          help='show and log the detail infomation')
        running_group.add_option("-f", "--script_file", action="store", type="string", dest="file_script",
                          help='set the script file include on_message')
        running_group.add_option("-c", "--config_file", action="store", type="string", dest="config",
                          help='load the options from the config file')
        running_group.add_option("-o", "--log_file", action="store", type="string", dest="log_file", default='',
                          help='set log file')
        parser.add_option_group(running_group)

        svr_group = OptionGroup(parser, 'Frida server Options')
        svr_group.add_option("", "--start_server", action="store_true", dest="start_server", default=False,
                          help='start the frida server')
        svr_group.add_option("", "--stop_server", action="store_true", dest="stop_server", default=False,
                          help='stop the frida server')
        svr_group.add_option("", "--status_server", action="store_true", dest="status_server", default=False,
                          help='get the status of frida server')
        parser.add_option_group(svr_group)













