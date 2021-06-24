#! /usr/bin/python
# -*-coding: UTF-8 -*-

import json
import os
from os.path import abspath, dirname
import importlib
from optparse import OptionGroup
from frida_hooks.utils import *
from frida_hooks.colors import *

_frida_cmds = [
    {'func': 'list_app', 'is_option': True, 'help': 'list all installed applications'},
    {'func': 'list_process', 'is_option': True, 'help': 'list processes'},
    {'api': 'listClass', 'func': 'list_class', 'is_option': True, 'help': 'list classes of Java'},
    {'api': 'listSo', 'func': 'list_so', 'is_option': True, 'help': 'list so'},
    {'api': 'listSoFunc', 'func': 'list_so_func', 'is_option': True,
     'help': 'list all functions of the so, Parameters: --module'},
    {'api': 'listThread', 'func': 'list_thread', 'is_option': True, 'help': 'list thread'},
    {'api': 'hookFunc', 'func': 'hook_func', 'is_option': True,
     'help': 'hook the method of one class, Parameters: --class, --func'},
    {'api': 'hookClass', 'func': 'hook_class', 'is_option': True,
     'help': 'hook all methods of one class, Parameters: --class'},
    {'api': 'hookSoFunc', 'func': 'hook_so_func', 'is_option': True,
     'help': 'hook the function of some module, Parameters: --module, (--func | --addr)'},
    {'api': 'hookSo', 'func': 'hook_so', 'is_option': True,
     'help': 'hook all functions of some module, Parameters: --module'},
    {'api': 'hookOkhttp3Execute', 'func': 'hook_okhttp3_execute', 'is_option': True,
     'help': 'hook okHttp3.RealCall.execute, suggest to use when viewing request'},
    {'api': 'hookOkhttp3Callserver', 'func': 'hook_okhttp3_CallServer', 'is_option': True,
     'help': 'hook okhttp3.CallServerInterceptor, suggest to use when viewing response'},
    {'api': 'hookIntercept', 'func': 'hook_intercept', 'is_option': True,
     'help': 'hook the intercept() of some okhttp3 interceptor, Parameters: --class'},
    {'api': 'hookRegisternatives', 'func': 'hook_RegisterNatives', 'is_option': True,
     'help': 'hook the RegisterNatives function, please use --suspend together'},
    {'api': 'dumpClass', 'func': 'dump_class', 'is_option': True, 'help': 'dump the class, Parameters: --class'},
    {'func': 'dump_so', 'is_option': True, 'help': 'dump so from memory to file, Parameters: --module'},
    {'func': 'dump_dex', 'is_option': True, 'help': 'dump dex from memory to file'},
    {'api': 'dumpSoMemory', 'func': 'dump_so_memory', 'is_option': True,
     'help': 'dump the memory of the module, Parameters: --module, --offset, --length'},
    {'api': 'searchInMemory', 'func': 'search_in_memory', 'is_option': False},
    {'api': 'memoryDump', 'func': 'memory_dump', 'is_option': False},
    {'api': 'scanDex', 'func': 'scan_dex', 'is_option': False},
    {'api': 'findSo', 'func': 'find_so', 'is_option': False},
]

_script_params = [
    {'name': 'module_name', "option_name": 'module', 'type': 'string', 'default': '', 'help': 'the name of so'},
    {'name': 'class_name', "option_name": 'class', 'type': 'string', 'default': '', 'help': 'the name of class'},
    {'name': 'func_name', "option_name": 'func', 'type': 'string', 'default': '', 'help': 'the name of function'},
    {'name': 'addr', "option_name": 'addr', 'type': 'string', 'default': '', 'help': 'the address of function in memory'},
    {'name': 'offset', "option_name": 'offset', 'type': 'string', 'default': '0', 'help': 'the offset to base address'},
    {'name': 'length', "option_name": 'length', 'type': 'string', 'default': '0',
     'help': 'length of the memory to dump or save'},
    {'name': 'deep_search', "option_name": 'deep_search', 'type': 'bool', 'default': False,
     'help': 'enable deep search maybe detected more dex, but speed will be slower'},
]

_script_colors = [
    {'name': 'col_hooked', 'value': Colors.hooked},
    {'name': 'col_keyword', 'value': Colors.keyword},
    {'name': 'col_keyword2', 'value': Colors.keyword2},
    {'name': 'col_keyword3', 'value': Colors.keyword3},
    {'name': 'col_path', 'value': Colors.path},
    {'name': 'col_title', 'value': Colors.title},
    {'name': 'col_column', 'value': Colors.column},
    {'name': 'col_exit', 'value': Colors.exit},
    {'name': 'col_reset', 'value': Colors.reset},
]


class Scriptor:
    _is_silence = False
    _show_detail = False
    _app_package = None

    def __init__(self):
        pass

    @staticmethod
    def set_app_package(app_package):
        Scriptor._app_package = app_package

    @staticmethod
    def set_silence(is_silence):
        Scriptor._is_silence = is_silence

    @staticmethod
    def set_show_detail(show_detail):
        Scriptor._show_detail = show_detail

    @staticmethod
    def get_core_script():
        color_scripts = []
        for item in _script_colors:
            color_scripts.append(f'let {item["name"]} = "{item["value"]}";')
        rpc_exports = []
        for item in _frida_cmds:
            if "api" in item.keys():
                rpc_exports.append(f'    {item["api"]}: {item["func"]},')
        export_script = '\nrpc.exports = {\n' + '\n'.join(rpc_exports) + '}\n'
        return "\n".join(color_scripts) + export_script + _script_core

    @staticmethod
    def add_cmd_options(parser):
        cmd_group = OptionGroup(parser, 'Command Options')
        for item in _frida_cmds:
            if "is_option" in item.keys() and item['is_option']:
                cmd_group.add_option("", f"--{item['func']}", action="store_true", dest=f"{item['func']}",
                                     default=False, help=f'{item["help"]}')
        parser.add_option_group(cmd_group)

    @staticmethod
    def print_cmds_help():
        print('Options:')
        for item in _frida_cmds:
            if "is_option" in item.keys() and item['is_option']:
                print(f"{Colors.keyword3}  --{item['func']}{Colors.reset}{' '*(25-len(item['func']))}{item['help']}")
        print('\nParameters:')
        for item in _script_params:
            print(f"{Colors.keyword3}  --{item['option_name']}{Colors.reset}{' '*(25-len(item['option_name']))}{item['help']}")

    @staticmethod
    def add_param_options(parser):
        param_group = OptionGroup(parser, 'Parameter Options')
        for item in _script_params:
            if item['type'] == 'string':
                param_group.add_option("", f"--{item['option_name']}", action="store", type="string",
                                       dest=f"{item['name']}", default=f"'{item['default']}'", help=f'{item["help"]}')
            else:
                param_group.add_option("", f"--{item['option_name']}", action="store_true", dest=f"{item['name']}",
                                       default={item['default']}, help=f'{item["help"]}')
        parser.add_option_group(param_group)

    @staticmethod
    def prepare_script(options):
        script = None
        cmd = Scriptor._get_option(options, "cmd", None)
        script_str = fun_on_msg = None
        file_script = Scriptor._get_option(options, "file_script", None)
        if file_script:
            script_str, fun_on_msg = Scriptor.load_script_file(file_script)
        if cmd == 'custom':
            if file_script:
                if script_str:
                    key = f'--file_script {file_script}'
                    script = {'script': script_str, 'cmd': 'custom', 'keepAlive': True, 'key': key, 'onMessage': Scriptor.on_message,
                              'isEnable': True, 'api_cmd': '', 'params': None}
                else:
                    print(f'Error: jscode not found in {file_script}!')
            else:
                print(f'{Colors.warning}custom: --file_script must be set{Colors.reset}')
        elif cmd:
            keep_alive = False
            if cmd == 'list_so_func' or cmd == 'hook_so':
                module = Scriptor._get_option(options, "module_name", '')
                if module != '':
                    key = f"--{cmd} --module {module}"
                    api_cmd = f'self._script.exports.{cmd}("{module}")'
                    keep_alive = (cmd == 'hook_so')
                    params = {'module': module}
                    script = {'cmd': cmd, 'key': key, 'api_cmd': api_cmd, 'params': params}
                else:
                    print(f'{Colors.warning}Usage: --{cmd} --module <so_name>{Colors.reset}')
            elif cmd == 'dump_so':
                module = Scriptor._get_option(options, "module_name", '')
                if module != '':
                    key = f"--{cmd} --module {module}"
                    save_file = f'/sdcard/Android/data/{Scriptor._app_package}/files/{module}'
                    api_cmd = f'self._script.exports.{cmd}("{module}", "{save_file}")'
                    params = {'module': module}
                    script = {'cmd': cmd, 'key': key, 'api_cmd': api_cmd, 'params': params}
                else:
                    print(f'{Colors.warning}Usage: --{cmd} --module <so_name>{Colors.reset}')
            elif cmd == 'dump_so_memory':
                module = Scriptor._get_option(options, "module_name", '')
                offset = Scriptor._get_option(options, "offset", '')
                length = Scriptor._get_option(options, "length", '')
                if module != '' and offset != '' and length != '':
                    key = f"--{cmd} --module {module} --offset {offset} --length {length}"
                    api_cmd = f'self._script.exports.{cmd}("{module}", {offset}, {length})'
                    params = {'module': module, 'offset': offset, 'length': length}
                    script = {'cmd': cmd, 'key': key, 'api_cmd': api_cmd, 'params': params}
                else:
                    print(f'{Colors.warning}Usage: --{cmd} --module <so_name> --offset <offset> --length <length>{Colors.reset}')
            elif cmd == 'hook_so_func':
                module = Scriptor._get_option(options, "module_name", '')
                func = Scriptor._get_option(options, "func_name", '')
                addr = Scriptor._get_option(options, "addr", '')
                if module != '' and (func != '' or addr != ''):
                    keep_alive = True
                    key = f"--{cmd} --module {module} {'--func %s' % func if func != '' else ''}{'--addr %s' % addr if addr != '' else ''}"
                    api_cmd = f'self._script.exports.{cmd}("{module}", "{func}", "{addr}")'
                    params = {'module': module, 'func': func, 'addr': addr}
                    script = {'cmd': cmd, 'key': key, 'api_cmd': api_cmd, 'params': params}
                else:
                    print(f'{Colors.warning}Usage: --{cmd} --module <so_name> <--func <func_name> | --addr <address>>{Colors.reset}')
            elif cmd == 'dump_class' or cmd == 'hook_class' or cmd == 'hook_intercept':
                class_name = Scriptor._get_option(options, "class_name", '')
                if class_name != '':
                    keep_alive = (cmd == 'hook_class' or cmd == 'hook_intercept')
                    key = f"--{cmd} --class {class_name}"
                    api_cmd = f'self._script.exports.{cmd}("{class_name}")'
                    params = {'class': class_name}
                    script = {'cmd': cmd, 'key': key, 'api_cmd': api_cmd, 'params': params}
                else:
                    print(f'{Colors.warning}Usage: --{cmd} --class <class_name>{Colors.reset}')
            elif cmd == 'hook_func':
                class_name = Scriptor._get_option(options, "class_name", '')
                func = Scriptor._get_option(options, "func_name", '')
                if class_name != '' and func != '':
                    key = f"--{cmd} --class {class_name} --func {func}"
                    api_cmd = f'self._script.exports.{cmd}("{class_name}", "{func}")'
                    params = {'class': class_name, 'func': func}
                    script = {'cmd': cmd, 'key': key, 'api_cmd': api_cmd, 'params': params}
                    keep_alive = True
                else:
                    print(f'{Colors.warning}Usage: --{cmd} --class <class_name> --func <func_name>{Colors.reset}')
            else:
                key = f"--{cmd}"
                api_cmd = f'self._script.exports.{cmd}()'
                script = {'cmd': cmd, 'key': key, 'api_cmd': api_cmd, 'params': None}
                keep_alive = (cmd == 'hook_okhttp3_CallServer' or cmd == 'hook_okhttp3_execute' or cmd == 'hook_RegisterNatives')
            if script:
                script['onMessage'] = Scriptor.on_message
                script['keepAlive'] = keep_alive
                script['isEnable'] = True

        if script:
            if fun_on_msg:
                script['onMessage'] = fun_on_msg
        return script

    @staticmethod
    def gen_script_str(scripts_map):
        fun_on_msg = Scriptor.on_message
        scripts_str = Scriptor.get_core_script()
        for key in scripts_map.keys():
            if scripts_map[key]['isEnable']:
                if 'script' in scripts_map[key].keys():
                    scripts_str += scripts_map[key]['script'] + '\n'
                fun_on_msg = scripts_map[key]['onMessage']
        return scripts_str, fun_on_msg

    @staticmethod
    def clean_scripts_map(scripts_map):
        new_map = {}
        for key in scripts_map.keys():
            if scripts_map[key]['keepAlive']:
                new_map[key] = scripts_map[key]
        return new_map

    @staticmethod
    def on_message(message, data):
        if message['type'] == 'send':
            msg_data = message['payload']
            if isinstance(msg_data, dict):
                Scriptor._handle_one_message(msg_data)
            elif isinstance(msg_data, list):
                for msg in msg_data:
                    if isinstance(msg, dict):
                        Scriptor._handle_one_message(msg)
                    else:
                        if not Scriptor._is_silence:
                            print_screen(msg)
                        write_log(msg)
            else:
                if not Scriptor._is_silence:
                    print_screen(msg_data)
                write_log(msg_data)
        else:
            if not Scriptor._is_silence:
                print_screen(message)
            write_log(message)

    @staticmethod
    def _handle_one_message(msg_data):
        text_to_print = ''
        if msg_data['type'] == 'stack' and Scriptor._show_detail:
            straces = re.split(',', msg_data['data'].encode('utf8', 'ignore').decode('utf8'))
            timestamp = ("[" + str(msg_data['timestamp']) + "]") if 'timestamp' in msg_data.keys() else ""
            if 'hookName' in msg_data.keys():
                text_to_print = Colors.title + ("---------------------  stack: %s %s ---------------------" % (
                    msg_data['funcName'], timestamp)) + Colors.reset + "\n    " + '\n    '.join(straces)
            else:
                text_to_print = Colors.title + (
                        "--------------------------  stack %s --------------------------" % timestamp) + Colors.reset \
                                + "\n    " + '\n    '.join(straces)
        elif msg_data['type'] == 'arguments':
            timestamp = ("[" + str(msg_data['timestamp']) + "]") if 'timestamp' in msg_data.keys() else ""
            args_before = json.loads(msg_data['before'])
            args_after = json.loads(msg_data['after'])
            arg_list = []
            for key in args_before.keys():
                if args_before[key] == args_after[key]:
                    arg_list.append('    ' + key + '\t' + Colors.keyword + str(args_before[key]) + Colors.reset)
                else:
                    arg_list.append('    *' + key + '\n    before: ' + Colors.keyword + str(args_before[key]) + Colors.reset \
                                    + '\n     after: ' + Colors.keyword + str(args_after[key]) + Colors.reset)
            if 'hookName' in msg_data.keys():
                text_to_print = Colors.title + (
                        "-------------------  arguments: %s %s -------------------" % (
                    msg_data['funcName'], timestamp)) + Colors.reset + "\n" + '\n'.join(arg_list)
            else:
                text_to_print = Colors.title + (
                        "------------------------  arguments %s ------------------------" % timestamp) + Colors.reset \
                                + "\n" + '\n'.join(arg_list)
        elif msg_data['type'] == 'asm_args':
            timestamp = ("[" + str(msg_data['timestamp']) + "]") if 'timestamp' in msg_data.keys() else ""
            args = msg_data['data']
            arg_list = []
            for key in args.keys():
                arg_list.append('    arg[' + key + ']=' + Colors.keyword + str(args[key]) + Colors.reset)
            if 'hookName' in msg_data.keys():
                text_to_print = Colors.title + (
                        "------------------------  arguments %s %s ------------------------" % (
                    msg_data['funcName'], timestamp)) + Colors.reset + "\n" + '\n'.join(arg_list)
            else:
                text_to_print = Colors.title + (
                        "------------------------  arguments %s ------------------------" % timestamp) + Colors.reset \
                                + "\n" + '\n'.join(arg_list)
        elif msg_data['type'] == 'fields' and Scriptor._show_detail:
            timestamp = ("[" + str(msg_data['timestamp']) + "]") if 'timestamp' in msg_data.keys() else ""
            fields_before = json.loads(msg_data['before'])
            fields_after = json.loads(msg_data['after']) if 'after' in msg_data.keys() else fields_before
            field_list = []
            for key in fields_before.keys():
                if fields_before[key]['value'] == fields_after[key]['value']:
                    field_info = "    field: " + Colors.keyword3 + key + Colors.reset \
                                 + "\tclass: " + fields_before[key]['class'] + "\tvalue: " + Colors.keyword2 + str(
                        fields_before[key]['value']) + Colors.reset
                else:
                    field_info = "   *field: " + Colors.keyword3 + key + Colors.reset \
                                 + "\tclass: " + fields_before[key]['class'] + "\n        value_before: " + Colors.keyword2 \
                                 + str(
                        fields_before[key]['value']) + Colors.reset + "\n         value_after: " + Colors.keyword2 \
                                 + str(fields_after[key]['value']) + Colors.reset
                field_list.append(field_info)
            if 'hookName' in msg_data.keys():
                text_to_print = Colors.title + (
                        "-------------------------  fields %s %s -------------------------" % (
                    msg_data['funcName'], timestamp)) + Colors.reset + "\n" + '\n'.join(field_list)
            else:
                text_to_print = Colors.title + (
                        "-------------------------  fields %s -------------------------" % timestamp) + Colors.reset \
                                + "\n" + '\n'.join(field_list)
        elif msg_data['type'] == 'return':
            timestamp = ("[" + str(msg_data['timestamp']) + "]") if 'timestamp' in msg_data.keys() else ""
            if 'hookName' in msg_data.keys():
                text_to_print = Colors.title + (
                        "--------------------  return: %s %s --------------------" % (
                    msg_data['funcName'], timestamp)) + Colors.reset + "\n    return: " + Colors.keyword + \
                                msg_data['value'] + Colors.reset
            else:
                text_to_print = Colors.title + (
                        "-------------------------  return %s -------------------------" % timestamp) + Colors.reset \
                                + "\n    return: " + Colors.keyword + msg_data['value'] + Colors.reset
        elif msg_data['type'] == 'registerNatives':
            methods = json.loads(msg_data['methods'])
            method_infos = []
            for item in methods:
                method_infos.append(
                    f'    {Colors.keyword}{item["java_class"]} {Colors.keyword3}{item["module_name"]} {Colors.reset}{item["fnPtr"]} {item["offset"]} {Colors.keyword2}{item["name"]}{Colors.reset} {item["sig"]}')
            text_to_print = Colors.title + (
                    "------------------------  registerNatives %s ------------------------" % len(
                methods)) + Colors.reset + "\n" + '\n'.join(method_infos)
        elif msg_data['type'] == 'request':
            timestamp = ("[" + str(msg_data['timestamp']) + "]") if 'timestamp' in msg_data.keys() else ""
            param_infos = Scriptor._parse_request(msg_data)
            text_to_print = Colors.title + \
                            ("------------------------  %s:request %s ------------------------\n" % (
                                msg_data['from'], timestamp)) + Colors.reset + '\n'.join(param_infos)
        elif msg_data['type'] == 'response':
            timestamp = ("[" + str(msg_data['timestamp']) + "]") if 'timestamp' in msg_data.keys() else ""
            response_infos = Scriptor._parse_response(msg_data)
            text_to_print = Colors.title + \
                            ("------------------------  %s:response %s ------------------------\n" % (
                                msg_data['from'], timestamp)) + Colors.reset + '\n'.join(response_infos)
        if not Scriptor._is_silence:
            print_screen(text_to_print.encode('gbk', 'ignore').decode('gbk'))
        write_log(text_to_print)

    @staticmethod
    def _parse_request(data):
        param_infos = []
        for key in ['method', 'url', 'headers', 'body']:
            if key != 'headers':
                if len(data[key]) > 0:
                    param = f'{Colors.keyword}{key}{Colors.reset}: {data[key].strip()}'
                else:
                    continue
            else:
                headers = data['headers'].strip().replace("\n", ", ")
                param = f'{Colors.keyword}headers{Colors.reset}: {headers}'
            param_infos.append(param)
        return param_infos

    @staticmethod
    def _parse_response(data):
        response = data['response'].strip()[9:-1]
        param_infos = []
        while len(response) > 0:
            param, response = Scriptor.__get_param_from_request(response)
            param_infos.append(param)
        if 'headers' in data.keys():
            headers = data['headers'].strip().replace("\n", ", ")
            param = f'{Colors.keyword}headers{Colors.reset}: {headers}'
            param_infos.append(param)
        if 'body' in data.keys() and len(data['body']) > 0:
            param = f'{Colors.keyword}body{Colors.reset}: {data["body"].strip()}'
            param_infos.append(param)
        return param_infos

    @staticmethod
    def __get_param_from_request(request):
        key, request = Scriptor.__get_key_from_request(request)
        value, request = Scriptor.__get_value_from_request(request)
        param = f'{Colors.keyword}{key}{Colors.reset}: {value}'
        return param, request

    @staticmethod
    def __get_key_from_request(request):
        idx = request.find("=")
        key = request[:idx]
        request = request[idx + 1:]
        return key, request

    @staticmethod
    def __get_value_from_request(request):
        if request[0] == '[':
            start = 1
            idx = request.find("],")
            next_start = idx + 3 if idx >= 0 else -1
        else:
            start = 0
            idx = request.find(",")
            next_start = idx + 2 if idx >= 0 else -1
        value = request[start:idx] if idx >= 0 else request[start:]
        request = request[next_start:] if next_start > 0 else ''
        return value, request

    @staticmethod
    def __load_script_file(file_script):
        script_str = fun_on_msg = None
        if file_script and file_script != '':
            mod = importlib.import_module(file_script)
            if mod:
                if mod.jscode:
                    script_str = mod.jscode
                if mod.on_message:
                    fun_on_msg = mod.on_message
        return script_str, fun_on_msg

    @staticmethod
    def _get_option(options, item, default=''):
        if isinstance(options, dict):
            if options['cf'].has_option(options['section'], item):
                return options['cf'].get(options['section'], item)
            else:
                return default
        elif isinstance(options, list):
            return Scriptor._get_option_from_cmd(options, item, default)
        else:
            return Scriptor._get_option_from_options(options, item, default)
    
    @staticmethod
    def _get_option_from_cmd(cmd, item, default=''):
        ret = default
        if cmd and len(cmd) > 1:
            if item == 'cmd':
                if len(cmd[1]) > 2:
                    ret = cmd[1][2:]
                else:
                    print(f'{Colors.warning}invalidate parameter: {cmd[1]}{Colors.reset}')
            else:
                param = item if item not in ['module_name', 'class_name', 'func_name'] else item[:-5]
                ret = Scriptor._get_internal_cmd_param(cmd, param, default)
        return ret
    
    @staticmethod
    def _get_internal_cmd_param(cmd, param, default=''):
        ret = default
        param = '--' + param
        for i in range(len(cmd)):
            if cmd[i] == param and i + 1 < len(cmd):
                return cmd[i + 1]
        return ret
    
    @staticmethod
    def _get_option_from_options(options, item, default=''):
        ret = default
        if item == 'cmd':
            for item in _frida_cmds:
                if "is_option" in item.keys() and item['is_option'] and getattr(options, item['func']):
                    return item['func']
            if options.file_script:
                ret = 'custom'
        else:
            ret = getattr(options, item)
        return ret

    @staticmethod
    def load_scripts():
        script_file = os.path.join(dirname(abspath(__file__)), 'scripts.js')
        with open(script_file, "r", encoding='utf-8') as f:
            return f.read()


_script_core = Scriptor.load_scripts()

