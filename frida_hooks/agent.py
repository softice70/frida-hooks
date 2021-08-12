#! /usr/bin/python
# -*-coding: UTF-8 -*-

import configparser
import os
from os.path import abspath, dirname
from optparse import OptionGroup
import frida
import hashlib
import _thread
import fnmatch
from http.server import HTTPServer
from frida_hooks.scriptor import Scriptor
from frida_hooks.utils import *
from frida_hooks.httphandler import HttpHandler


md5 = lambda bs: hashlib.md5(bs).hexdigest()


class FridaAgent:
    _frida_server_path = '/data/local/tmp/frida-server'

    def __init__(self, parser=None):
        self._parser = parser
        self._device = None
        self._session = None
        self._script = None
        self._script_src = None
        self._app_package = None
        self._scripts_map = {}
        self._is_app_suspend = False
        self._target_pid = -1
        self._keep_running = False
        self._init_parser(self._parser)
        self._enable_deep_search_for_dump_dex = False
        self._imp_mods = {}
        self._is_start_httpd = (parser is not None)
        self._host = "127.0.0.1"
        self._port = 8989
        self._httpd = None
        self._fh_log = None
        pass

    def get_device_id(self):
        return self._device.id if self._device else ''

    def load_script(self, scripts_str, fun_on_msg, wait_time_in_sec=10):
        self._script_src = re.split('\n', scripts_str)
        self._script = None
        ret = False
        self._script = self._session.create_script(scripts_str)
        self._script.on("message", fun_on_msg)
        for i in range(wait_time_in_sec):
            try:
                self._script.load()
                if self._is_app_suspend:
                    self._exec_script_in_spawn_mode()
                    self._exec_script_cmd_after_load()
                    self._device.resume(self._target_pid)
                    self._is_app_suspend = False
                else:
                    self._exec_script_cmd_after_load()
                ret = True
                break
            except Exception as e:
                print(f'load:{e}')
                time.sleep(1)
                pass
        self._script.exports.set_color_mode(get_color_mode())
        self._scripts_map = Scriptor.clean_scripts_map(self._scripts_map)
        return ret

    def unload_script(self):
        if self._script and self._session:
            self._script.unload()

    def start_app(self, app_name, is_suspend=False):
        self._app_package = app_name
        if self.start_frida_server() > 0:
            self._app_package, pid = self._confirm_package_pid(app_name)
            if not is_suspend:
                self._target_pid = pid
                if self._target_pid > 0:
                    if self._attach_app():
                        app_ver = get_app_version(self._device.id, self._app_package)
                        print(f'{self._app_package}[pid:{clr_cyan(self._target_pid)} version:{clr_cyan(app_ver)}] is already running...')
            if self._target_pid <= 0:
                self._target_pid = self._start_app_by_package_name(self._app_package, is_suspend)
        return self._target_pid > 0

    def run(self):
        try:
            (options, args) = self._parser.parse_args()
            if options.monochrome:
                set_color_mode(False)
            if not self.init_device(device_id=options.device_id):
                self.exit()
                return
            if len(args) == 0 and not options.config:
                self._exec_internal_cmd(options)
            elif len(args) > 1:
                self._parser.print_help()
            else:
                if options.config:
                    self._keep_running = self._load_config(options.config)
                else:
                    self._app_package = args[0]
                    self._load_options(options)
                    self._keep_running = True
                if self._keep_running:
                    self._keep_running = self.start_app(self._app_package, is_suspend=options.is_suspend)
                self._start_http_server()
                self._print_internal_cmd_help()
                while self._keep_running:
                    scripts_str, fun_on_msg = Scriptor.gen_script_str(self._scripts_map)
                    if not self.load_script(scripts_str, fun_on_msg):
                        self._print_internal_cmd_help()
                    self._run_console()
                    self.unload_script()
        except Exception as e:
            print(f'run:{e}')
        self.exit()

    def exec_one_script(self, script):
        ret = None
        if script['isEnable']:
            try:
                if script['cmd'] == 'dump_dex':
                    self._dump_dex()
                elif script['cmd'] == 'dump_so':
                    self._dump_so(script)
                elif script['cmd'] == 'save_apk':
                    self.save_apk(self._app_package)
                elif script['cmd'] == 'list_app':
                    self.list_app(check_frida_server=False)
                elif script['cmd'] == 'list_device':
                    self.list_device()
                elif script['cmd'] == 'list_process':
                    self.list_process(False)
                elif script['cmd'] == 'search_app':
                    self.list_app(app_name=script['params']['app'], check_frida_server=False)
                elif script['cmd'] == 'app_version':
                    self._show_version(script['params']['app'])
                elif script['apiCmd'] != '':
                    ret = eval(script['apiCmd'])
            except Exception as e:
                print(clr_red(f'\nError: {e}\n  cmd: {script["key"]}'))
                script['isEnable'] = False
                pass
        return ret

    def exit(self):
        if self._session:
            self._session.detach()
        print(clr_bright_gray(clr_reverse('frida hooker exited.')))

    def start_frida_server(self):
        name = re.split('/', FridaAgent._frida_server_path)[-1]
        frida_server_pid = get_pid_by_adb_shell(self._device.id, FridaAgent._frida_server_path)
        if frida_server_pid > 0:
            print(f'{name}[pid:{clr_cyan(frida_server_pid)}] is already running...')
            return frida_server_pid
        else:
            self.__start_frida_server()
            sid = get_pid_by_adb_shell(self._device.id, FridaAgent._frida_server_path, 10)
            if sid < 0:
                print(f"error: frida server {FridaAgent._frida_server_path} failed to start")
            else:
                print(f'{FridaAgent._frida_server_path}[pid:{clr_cyan(sid)}] is running...')
            return sid

    def stop_frida_server(self):
        name = re.split('/', FridaAgent._frida_server_path)[-1]
        frida_server_pid = get_pid_by_adb_shell(self._device.id, FridaAgent._frida_server_path)
        if frida_server_pid < 0:
            print(f'{name} is not running')
        else:
            cmd = f'adb -s {self._device.id} shell su -c "kill -9 {frida_server_pid}"'
            exec_cmd(cmd, 10)
            print(f'{name}[pid:{frida_server_pid}] is stop')

    def show_frida_server_status(self, wait_time_in_sec=1):
        name = re.split('/', FridaAgent._frida_server_path)[-1]
        frida_server_pid = get_pid_by_adb_shell(self._device.id, FridaAgent._frida_server_path, wait_time_in_sec)
        if frida_server_pid < 0:
            print(f'{name} is not running')
        else:
            print(f'{name}[pid:{clr_cyan(frida_server_pid)}] is running...')

    def get_app_version(self, app_name):
        if app_name and app_name != '':
            return get_app_version(self._device.id, app_name)
        else:
            return ''

    @staticmethod
    def list_device():
        devices = frida.get_device_manager().enumerate_devices()
        print('List of devices attached:')
        for device in devices:
            if device.type == 'usb':
                print(f'id: {clr_cyan(device.id)}\tname:{clr_yellow(device.name)}')
        return devices

    def list_app(self, app_name=None, check_frida_server=True):
        if not check_frida_server or self.start_frida_server() > 0:
            app_list = self._device.enumerate_applications()
            app_list.sort(key=lambda s: s.identifier)
            if not app_name:
                matching = app_list
            else:
                app_lc = app_name.lower()
                matching = [proc for proc in app_list
                            if proc.name.lower().find(app_lc) >= 0 or proc.identifier.find(app_name) >= 0]
            for item in matching:
                if item.pid > 0:
                    print(f'{clr_yellow(item.pid):<21}{clr_bright_cyan(item.identifier):<60}{clr_yellow(item.name)}')
                else:
                    print(f'{item.pid:<10}{clr_bright_cyan(item.identifier):<60}{clr_purple(item.name)}')
        else:
            raise Exception()

    def find_app(self, app):
        if app and app != '':
            app_lc = app.lower()
            matching = [proc for proc in self._device.enumerate_applications()
                        if fnmatch.fnmatchcase(proc.identifier, app) or fnmatch.fnmatchcase(proc.name.lower(), app_lc)]
            if len(matching) == 1:
                version = self.get_app_version(matching[0].identifier)
                return {"pid": matching[0].pid, "identifier": matching[0].identifier, "name": matching[0].name, "version": version}
        return None

    def save_apk(self, app):
        app_info = self.find_app(app)
        if app_info:
            identifier = app_info["identifier"]
            cmd = f'adb -s {self._device.id} shell su -c "cp /data/app/{identifier}-1/base.apk /sdcard/{identifier}.apk"'
            exec_cmd(cmd, 30)
            cmd = f'adb -s {self._device.id} pull /sdcard/{identifier}.apk"'
            exec_cmd(cmd, 30)
            cmd = f'adb -s {self._device.id} shell su -c "rm -f /sdcard/{identifier}.apk"'
            exec_cmd(cmd, 30)
            if os.path.exists(f'{identifier}.apk'):
                print(f'apk file saved in {clr_blue(abspath(identifier + ".apk"))}.')
            else:
                print(clr_red('failed to the apk file.'))

    def list_process(self, check_frida_server=True):
        if not check_frida_server or self.start_frida_server() > 0:
            proc_list = self._device.enumerate_applications()
            proc_list.sort(key=lambda s: s.identifier)
            for proc in proc_list:
                if proc.pid > 0:
                    print(f'{proc.pid:<10}{clr_bright_cyan(proc.identifier):<60}{clr_yellow(proc.name)}')
        else:
            raise Exception()

    def get_rpc_exports(self):
        return self._script.exports if self._script else None

    @staticmethod
    def _init_parser(parser):
        if parser:
            parser.remove_option('-h')
            Scriptor.add_cmd_options(parser)
            Scriptor.add_param_options(parser)

            running_group = OptionGroup(parser, 'Running Options')
            running_group.add_option("-S", "--spawn", action="store_true", dest="is_suspend", default=False,
                                     help='spawn mode of Frida, that suspend app during startup')
            running_group.add_option("-i", "--device_id", action="store", type="string", dest="device_id", default='',
                                     help='attach the specified device')
            running_group.add_option("-m", "--monochrome", action="store_true", dest="monochrome", default=False,
                                     help='set to monochrome mode')
            running_group.add_option("-h", "--host", action="store", type="string", dest="host", default="127.0.0.1",
                                     help='the ip of http server, default: 127.0.0.1')
            running_group.add_option("-p", "--port", action="store", type="int", dest="port", default=8989,
                                     help='the port of http server, default: 8989')
            running_group.add_option("", "--silence", action="store_true", dest="silence", default=False,
                                     help='no message is output to screen')
            running_group.add_option("-d", "--show_detail", action="store_true", dest="show_detail", default=True,
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

    @staticmethod
    def _print_internal_cmd_help():
        help_strs = [
            f'Usage: cmd [option]\ncmd:',
            f'\n  {clr_yellow("h")}{clr_bright_cyan("elp")}{" "*(32-len("help"))}show this help message',
            f'\n  {clr_yellow("r")}{clr_bright_cyan("un [options]")}{" "*(32-len("run [options]"))}run hook option, see also <{clr_bright_cyan("options")}>',
            f'\n  {clr_yellow("o")}{clr_bright_cyan("ptions")}{" "*(32-len("options"))}print options',
            f'\n  {clr_yellow("l")}{clr_bright_cyan("ist")}{" "*(32-len("list"))}show hook list',
            f'\n  {clr_yellow("d")}{clr_bright_cyan("isable <key>")}{" "*(32-len("disable <key>"))}set disable the hook item by key',
            f'\n  {clr_yellow("e")}{clr_bright_cyan("nable <key>")}{" "*(32-len("enable <key>"))}set enable the hook item by key',
            f'\n  {clr_bright_cyan("re")}{clr_yellow("m")}{clr_bright_cyan("ove <key>")}{" "*(32-len("remove <key>"))}remove the hook item by key',
            f'\n  {clr_yellow("c")}{clr_bright_cyan("onfig <file>")}{" "*(32-len("config <file>"))}load the config file',
            f'\n  {clr_bright_cyan("lo")}{clr_yellow("g")}{clr_bright_cyan(" [file]")}{" "*(32-len("log [file]"))}set the log file, and if file is not set, the log will be turned off',
            f'\n  {clr_bright_cyan("re")}{clr_yellow("s")}{clr_bright_cyan("tart")}{" "*(32-len("restart"))}restart the hook session',
            f'\n  {clr_bright_cyan("de")}{clr_yellow("t")}{clr_bright_cyan("ail")}{" "*(32-len("detail"))}toggles whether to display details',
            f'\n  {clr_bright_cyan("script [line number]")}{" "*(32-len("script [line number]"))}show source code of script',
            f'\n  {clr_bright_cyan("cls")}{" "*(32-len("cls"))}clear screen',
            f'\n  {clr_yellow("q")}{clr_bright_cyan("uit")}{" "*(32-len("quit"))}quit'
        ]
        print("".join(help_strs))

    def __start_frida_server(self):
        print(f'{FridaAgent._frida_server_path} is starting...')

        def kill_process():
            try:
                p.kill()
            except OSError:
                pass  # Swallow the error

        cmd = f'adb -s {self._device.id} shell su -c "{FridaAgent._frida_server_path} &"'
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        timer = Timer(3, kill_process)
        timer.start()
        p.wait()
        timer.cancel()

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
        _id = 0
        for key in scripts_map.keys():
            scripts_map[key]["id"] = _id
            _id += 1
            if scripts_map[key]['isEnable']:
                print(f'{scripts_map[key]["id"]:>3}[{clr_bright_green("✓")}] {clr_yellow(key)}')
            else:
                print(f'{scripts_map[key]["id"]:>3}[{clr_bright_green("✗")}] {clr_dark_gray(key)}')

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

    def _load_config(self, cfg_file):
        ret = False
        if os.path.exists(cfg_file):
            try:
                cf = configparser.ConfigParser()
                cf.read(cfg_file, 'utf-8')
                app_package = cf.get("main", "app_package")
                log_file = cf.get("main", "log_file") if cf.has_option("main", "log_file") else ''
                self._host = int(cf.get("main", "host")) if cf.has_option("main", "host") else self._host
                self._port = int(cf.get("main", "port")) if cf.has_option("main", "port") else self._port
                Scriptor.set_silence(
                    cf.get("main", "silence").lower() == 'true' if cf.has_option("main", "silence") else False)
                Scriptor.set_show_detail(
                    cf.get("main", "show_detail").lower() == 'true' if cf.has_option("main", "show_detail") else False)
                Scriptor.reset_frida_cmds()
                self._open_logger(log_file)
                if not self._app_package or self._app_package == app_package:
                    self._app_package = app_package
                    configs = re.split(',', cf.get("main", "load_configs"))
                    for item in configs:
                        script = Scriptor.prepare_script({'cf': cf, 'section': item}, self._imp_mods)
                        if script:
                            self._scripts_map[script['key']] = script
                    ret = True
                    print(f'{clr_bright_purple(cfg_file)} is loaded...')
                else:
                    print(clr_bright_red("warning: invalidate app_package:[") + clr_bright_cyan(app_package)
                          + clr_bright_red("] in the config:[") + clr_bright_cyan(cfg_file) + clr_bright_red("]"))
            except Exception as e:
                print(e)
            finally:
                return ret
        else:
            print(f'{clr_bright_red("warning: config file not found! - ")}{clr_bright_cyan(cfg_file)}')
            return ret

    def _load_options(self, options):
        self._host = options.host
        self._port = options.port
        Scriptor.set_silence(options.silence)
        Scriptor.set_show_detail(options.show_detail)
        script = Scriptor.prepare_script(options, self._imp_mods)
        if script:
            self._scripts_map[script['key']] = script
        self._open_logger(options.log_file)
        return self._scripts_map

    def _open_logger(self, log_file):
        if self._fh_log:
            logger.removeHandler(self._fh_log)
            self._fh_log = None
        if log_file != '':
            logger.setLevel(logging.INFO)
            # create file handler which logs even debug messages
            self._fh_log = logging.FileHandler(log_file, encoding='utf-8')
            self._fh_log.setLevel(logging.INFO)
            formatter = logging.Formatter("%(asctime)s  %(name)s  %(levelname)s  %(message)s")
            self._fh_log.setFormatter(formatter)
            # add the handlers to logger
            logger.addHandler(self._fh_log)
            print(f'log file: {clr_blue(abspath(self._fh_log.baseFilename))}')
        else:
            print(f'log is turned off.')

    def _start_http_server(self):
        HttpHandler.set_agent(self)
        self._httpd = HTTPServer((self._host, self._port), HttpHandler)
        _thread.start_new_thread(lambda: self._httpd.serve_forever(), ())
        print(f'http server[{clr_cyan(self._host + ":" + str(self._port))}] is running...')
        print(f'rpc: {clr_yellow("POST")} {clr_cyan("http://" + self._host + ":" + str(self._port) + "/run")}')

    def _start_app_by_package_name(self, package, is_suspend=False):
        if package is None or package == '':
            self._target_pid = -1
        else:
            retry_times = 5
            for i in range(retry_times):
                self._target_pid = self._device.spawn(package) if is_suspend else self._start_app_by_monkey(package)
                time.sleep(i)
                self._is_app_suspend = True
                if self._target_pid > 0:
                    app_ver = get_app_version(self._device.id, self._app_package)
                    print(f'{package}[pid:{clr_cyan(self._target_pid)} version:{clr_cyan(app_ver)}] is running...')
                    if not is_suspend:
                        self._is_app_suspend = False
                    if self._attach_app():
                        break
        return self._target_pid

    def _start_app_by_monkey(self, package):
        cmd = f"adb -s {self._device.id} shell monkey -p {package} -c android.intent.category.LAUNCHER 1"
        exec_cmd(cmd, 10)
        return self._get_process_id(package)

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

    def _is_app_running(self):
        pid = self._get_process_id(self._app_package)
        ret = (pid == self._target_pid)
        self._target_pid = pid
        return ret

    def _exec_cmd_disable_and_enable(self, cmd, isEnable):
        ret = False
        if len(cmd) >= 2:
            key = ' '.join(cmd[1:])
            if key not in self._scripts_map.keys():
                if key == '*':
                    for k in self._scripts_map.keys():
                        self._scripts_map[k]['isEnable'] = isEnable
                        ret = True
                elif is_number(key):
                    real_key = None
                    for k in self._scripts_map.keys():
                        if self._scripts_map[k]["id"] == int(key):
                            real_key = k
                            break
                    if real_key:
                        self._scripts_map[k]['isEnable'] = isEnable
                        ret = True
                if not ret:
                    print(f'key:{clr_bright_purple(key)} not found')
            else:
                if self._scripts_map[key]['isEnable'] != isEnable:
                    self._scripts_map[key]['isEnable'] = isEnable
                    ret = True
                else:
                    print(
                        f'hook: {clr_bright_cyan(key)} has already been set to {clr_bright_purple(isEnable)}')
        else:
            self._print_internal_cmd_help()
        if ret:
            self._print_hook_info(self._scripts_map)
        return ret

    def _exec_cmd_remove_hook_item(self, cmd):
        ret = False
        if len(cmd) >= 2:
            key = ' '.join(cmd[1:])
            if key not in self._scripts_map.keys():
                if key == '*':
                    self._scripts_map.clear()
                    ret = True
                elif is_number(key):
                    real_key = None
                    for k in self._scripts_map.keys():
                        if self._scripts_map[k]["id"] == int(key):
                            real_key = k
                            break
                    if real_key:
                        del self._scripts_map[real_key]
                        ret = True
                if not ret:
                    print(f'key:{clr_bright_purple(key)} not found')
            else:
                del self._scripts_map[key]
                ret = True
        else:
            self._print_internal_cmd_help()
        return ret

    def _exec_script_cmd_after_load(self):
        for key in self._scripts_map.keys():
            self.exec_one_script(self._scripts_map[key])

    def _exec_script_in_spawn_mode(self):
        self._script.exports.hook_lib_art()

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
                elif cmd[0] == 'log' or cmd[0] == 'g':
                    if len(cmd) == 2:
                        self._open_logger(cmd[1])
                    elif len(cmd) == 1:
                        self._open_logger('')
                    else:
                        print(f'usage: {clr_bright_cyan("lo")}{clr_yellow("g")}{clr_bright_cyan(" <file>")}')
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
                elif cmd[0] == 'detail' or cmd[0] == 't':
                    Scriptor.set_show_detail(not Scriptor.get_show_detail())
                    print_screen(f"show detail: {clr_yellow(str(Scriptor.get_show_detail()))}")
                elif cmd[0] == 'cls':
                    os.system('cls')
                elif cmd[0] == 'run' or cmd[0] == 'r':
                    self._exec_cmd_run(cmd)
                elif cmd[0] == 'script':
                    if self._print_script(cmd):
                        break
                else:
                    print(f'{clr_bright_red("unknown command!")}')
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
                self.exec_one_script(script)
                if script['persistent']:
                    self._scripts_map[script['key']] = script
        else:
            self._print_internal_cmd_help()

    def init_device(self, device_id=''):
        self._device = None
        if device_id == '':
            self._device = frida.get_usb_device(timeout=15)
        else:
            devices = frida.get_device_manager().enumerate_devices()
            for device in devices:
                if device.id == device_id and device.type == 'usb':
                    self._device = device
                    break
        if self._device:
            print(f'device [{clr_cyan(self._device.id)}] connected.')
            sys.path.append(os.getcwd())
        else:
            print(clr_red(f'device ID[{device_id}] not found.'))
        return self._device

    def _exec_internal_cmd(self, options):
        if options.start_server:
            self.start_frida_server()
        elif options.stop_server:
            self.stop_frida_server()
        elif options.status_server:
            self.show_frida_server_status()
        elif options.list_device:
            self.list_device()
        elif options.list_app:
            self.list_app(check_frida_server=True)
        elif options.search_app:
            self.list_app(app_name=options.app_name, check_frida_server=True)
        elif options.app_version:
            self._show_version(options.app_name)
        elif options.list_process:
            self.list_process(check_frida_server=True)
        else:
            self._parser.print_help()

    def _confirm_package_pid(self, app):
        app_list = self._device.enumerate_applications()
        if is_number(app):
            pid = int(app)
            matching = [proc for proc in app_list if proc.pid == pid]
        else:
            app_lc = app.lower()
            matching = [proc for proc in app_list if fnmatch.fnmatchcase(proc.identifier, app) or fnmatch.fnmatchcase(proc.name.lower(), app_lc)]
        if len(matching) == 1:
            return matching[0].identifier, matching[0].pid
        else:
            print(clr_red(f'app: \"{app}\" not found!'))
            return None, -1

    def _get_process_id(self, app):
        matching = [proc for proc in self._device.enumerate_applications() if fnmatch.fnmatchcase(proc.identifier, app)]
        return matching[0].pid if len(matching) == 1 else -1

    def _get_process_name(self, pid):
        matching = [proc for proc in self._device.enumerate_applications() if fnmatch.fnmatchcase(proc.pid, pid)]
        return matching[0].identifier if len(matching) == 1 else None

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
                print(clr_bright_green(f'[DumpSo]: Base={info["base"]}, Size={hex(info["size"])}, SavePath=')
                      + clr_bright_blue(clr_underline(f"{os.getcwd()}/{fixed_so_path}")))
            except Exception as e:
                print(clr_bright_red(f"[Except] - {e}: {info}"))
            print_screen(clr_bright_green(f'{module_name} dump finished!'))

    def _dump_dex(self):
        if self._enable_deep_search_for_dump_dex:
            print(clr_yellow("[DEXDump]: deep search mode is enable, maybe wait long time."))

        mds = []
        print(clr_bright_green('scanning dex in memory...'))
        matches = self._script.exports.scan_dex(self._enable_deep_search_for_dump_dex)
        i = 0
        for info in matches:
            try:
                bs = self._script.exports.memory_dump(info['addr'], info['size'])
                md = md5(bs)
                if md in mds:
                    print(clr_yellow(f"[DEXDump]: Skip duplicate dex {info['addr']}<{md}>"))
                    continue
                mds.append(md)
                if not os.path.exists("./" + self._app_package + "/"):
                    os.mkdir("./" + self._app_package + "/")
                bs = self._dex_fix(bs)
                with open(f'{self._app_package}/class{i if i != 0 else ""}.dex', 'wb') as out:
                    out.write(bs)
                    print(clr_bright_green(f"[DEXDump]: DexSize={clr_cyan(hex(info['size'])):<20} DexMd5={clr_purple(md)} SavePath=")
                        + clr_bright_blue(clr_underline(f"{os.getcwd()}/{self._app_package}/class{i if i != 0 else ''}.dex")))
                    i += 1
            except Exception as e:
                print(clr_bright_red(f"[Except] - {e}: {info}"))
        print_screen(clr_bright_green('Dex dump finished!'))

    def _print_script(self, cmd):
        line_no = None
        start_line = 0
        end_line = len(self._script_src) - 1
        if len(cmd) == 2 and is_number(cmd[1]):
            line_no = max(int(cmd[1]) - 1, 0)
            start_line = max(line_no - 10, 0)
            end_line = min(start_line + 21, len(self._script_src) - 1)
            start_line = max(end_line - 21, 0)

        for i in range(start_line, end_line + 1):
            if i == line_no:
                print(f'{clr_yellow("==> ")}{clr_bright_cyan(str(i+1)):<20}{self._script_src[i]}')
            else:
                print(f'    {clr_bright_cyan(str(i+1)):<20}{self._script_src[i]}')

    def _show_version(self, app_name):
        if app_name and app_name != '':
            app_ver = get_app_version(self._device.id, app_name)
            print(f'app:{clr_cyan(app_name)} version:{clr_cyan(app_ver)}')
        elif self._app_package:
            app_ver = get_app_version(self._device.id, self._app_package)
            print(f'app:{clr_cyan(self._app_package)} version:{clr_cyan(app_ver)}')
        else:
            print(Scriptor.get_cmd_usage('app_version'))

