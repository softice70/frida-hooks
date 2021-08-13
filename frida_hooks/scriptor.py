#! /usr/bin/python
# -*-coding: UTF-8 -*-

import json
import os
from os.path import abspath, dirname
import importlib
from optparse import OptionGroup
from frida_hooks.utils import *
from frida_hooks.colors import *


class ArgumentsErrorException(Exception): pass


class Scriptor:
    _original_frida_cmds = [
        {'func': 'list_device', 'persistent': False, 'is_option': True, 'help': 'list the device'},
        {'func': 'list_app', 'persistent': False, 'is_option': True, 'help': 'list all installed applications'},
        {'func': 'list_process', 'persistent': False, 'is_option': True, 'help': 'list processes'},
        {'api': 'loadAllClass', 'func': 'load_all_class', 'persistent': False, 'is_option': True, 'help': 'load class'},
        {'api': 'listClass', 'func': 'list_class', 'persistent': False, 'is_option': True,
         'help': 'list classes of Java'},
        {'api': 'listClassLoaders', 'func': 'list_class_loaders', 'persistent': False, 'is_option': True,
         'help': 'list class loaders'},
        {'api': 'listActivities', 'func': 'list_activities', 'is_option': True, 'persistent': False,
         'help': 'list activities'},
        {'api': 'listCurrentActivity', 'func': 'list_current_activity', 'is_option': True, 'persistent': False,
         'help': 'list current activity and fragment'},
        {'api': 'listServices', 'func': 'list_services', 'is_option': True, 'persistent': False,
         'help': 'list services'},
        {'api': 'listBroadcastReceivers', 'func': 'list_broadcast_receivers', 'is_option': True, 'persistent': False,
         'help': 'list services'},
        {'api': 'listSo', 'func': 'list_so', 'persistent': False, 'is_option': True, 'help': 'list so'},
        {'api': 'listSoFunc', 'func': 'list_so_func', 'persistent': False, 'is_option': True,
         'help': 'list all functions of the so',
         'params': [{"name": "module", "type": "string"}]},
        {'api': 'listRegisterNatives', 'func': 'list_register_natives', 'persistent': False, 'is_option': True,
         'help': 'list the register natives function, please use --spawn to start the frida-hooks'},
        {'api': 'listThread', 'func': 'list_thread', 'persistent': False, 'is_option': False, 'help': 'list thread'},
        {'api': 'hookFunc', 'func': 'hook_func', 'persistent': True, 'is_option': True,
         'help': 'hook the method of one class',
         'params': [{"name": "class", "type": "string"}, {"name": "func", "type": "string"}]},
        {'api': 'hookClass', 'func': 'hook_class', 'persistent': True, 'is_option': True,
         'help': 'hook all methods of one class',
         'params': [{"name": "class", "type": "string"}]},
        {'api': 'hookSoFunc', 'func': 'hook_so_func', 'persistent': True, 'is_option': True,
         'help': 'hook the function of some module',
         'params': [
             {"name": "module", "type": "string"},
             {"name": "func", "type": "string", "isOptional": True},
             {"name": "addr", "type": "string", "isOptional": True}
         ]},
        {'api': 'hookSo', 'func': 'hook_so', 'persistent': True, 'is_option': True,
         'help': 'hook all functions of some module',
         'params': [{"name": "module", "type": "string"}]},
        {'api': 'hookHttpExecute', 'func': 'hook_http_execute', 'persistent': True, 'is_option': True,
         'help': 'batch execute hook_http_url_connection, hook_okhttp_execute and hook_okhttp3_execute'},
        {'api': 'hookHttpUrlConnection', 'func': 'hook_http_url_connection','is_option': True,
         'help': 'hook com.android.okhttp.internal.huc.HttpURLConnectionImpl.execute()', 'persistent': False},
        {'api': 'hookOkhttpExecute', 'func': 'hook_okhttp_execute', 'persistent': True, 'is_option': True,
         'help': 'hook com.android.okhttp.Call.execute(), suggest to use when viewing request'},
        {'api': 'hookOkhttp3Execute', 'func': 'hook_okhttp3_execute', 'persistent': True, 'is_option': True,
         'help': 'hook okHttp3.RealCall.execute(), suggest to use when viewing request'},
        {'api': 'hookOkhttp3Callserver', 'func': 'hook_okhttp3_CallServer', 'persistent': True, 'is_option': True,
         'help': 'hook okhttp3.CallServerInterceptor, suggest to use when viewing response'},
        {'api': 'hookIntercept', 'func': 'hook_intercept', 'persistent': True, 'is_option': True,
         'help': 'hook the intercept() of some okhttp3 interceptor',
         'params': [{"name": "class", "type": "string"}]},
        {'api': 'hookJsonParser', 'func': 'hook_json_parser', 'persistent': True, 'is_option': True,
         'help': 'hook several common JSON parser',
         'params': [{"name": "keyword", "type": "string", "isOptional": True}]},
        {'api': 'dumpClass', 'func': 'dump_class', 'persistent': False, 'is_option': True,
         'help': 'dump the class',
         'params': [{"name": "class", "type": "string"}]},
        {'func': 'dump_so', 'persistent': False, 'is_option': True,
         'help': 'dump so from memory to file',
         'params': [{"name": "module", "type": "string"}]},
        {'func': 'dump_dex', 'persistent': False, 'is_option': True,
         'help': 'dump dex files, please use --spawn to start the frida-hooks'},
        {'func': 'save_apk', 'persistent': False, 'is_option': True,
         'help': 'save APK file to local directory'},
        {'api': 'dumpSoMemory', 'func': 'dump_so_memory', 'persistent': False, 'is_option': True,
         'help': 'dump the memory of the module, Parameters: --module, --offset, --length',
         'params': [
             {"name": "module", "type": "string"},
             {"name": "offset", "type": "int"},
             {"name": "length", "type": "int"}
         ]},
        {'func': 'search_app', 'persistent': False, 'is_option': True,
         'help': 'search the specified app',
         'params': [{"name": "app", "type": "string"}]},
        {'api': 'searchClass', 'func': 'search_class', 'persistent': False, 'is_option': True,
         'help': 'search the class that contains the specified keyword',
         'params': [{"name": "keyword", "type": "string"}]},
        {'api': 'searchFunc', 'func': 'search_func', 'persistent': False, 'is_option': True,
         'help': 'search the specified method exactly',
         'params': [
             {"name": "func", "type": "string"},
             {"name": "exclude", "type": "string", "isOptional": True}
         ]},
        {'api': 'fuzzySearchFunc', 'func': 'fuzzy_search_func', 'persistent': False, 'is_option': True,
         'help': 'search the method that contains the specified keyword',
         'params': [
             {"name": "keyword", "type": "string"},
             {"name": "exclude", "type": "string", "isOptional": True}
         ]},
        {'api': 'searchReturn', 'func': 'search_return', 'persistent': False, 'is_option': True,
         'help': 'search the specified type of return value',
         'params': [
             {"name": "type", "type": "string"},
             {"name": "exclude", "type": "string", "isOptional": True}
         ]},
        {'api': 'searchInstance', 'func': 'search_instance', 'persistent': False, 'is_option': True,
         'help': 'search the instance of class',
         'params': [{"name": "class", "type": "string"}]},
        {'api': 'openSchemeUrl', 'func': 'open_scheme_url', 'persistent': False, 'is_option': True,
         'help': 'open an activity by scheme url',
         'params': [{"name": "url", "type": "string"}]},
        {'api': 'startActivity', 'func': 'start_activity', 'persistent': False, 'is_option': True,
         'help': 'start the specified Activity',
         'params': [{"name": "activity", "type": "string"}]},
        {'func': 'app_version', 'persistent': False, 'is_option': True,
         'help': 'show the version of specified app',
         'params': [{"name": "app", "type": "string", "isOptional": True}]},
        {'api': 'searchInMemory', 'func': 'search_in_memory', 'persistent': False, 'is_option': False},
        {'api': 'memoryDump', 'func': 'memory_dump', 'persistent': False, 'is_option': False},
        {'api': 'scanDex', 'func': 'scan_dex', 'persistent': False, 'is_option': False},
        {'api': 'hookLibArt', 'func': 'hook_lib_art', 'persistent': False, 'is_option': False},
        {'api': 'findSo', 'func': 'find_so', 'persistent': False, 'is_option': False},
        {'api': 'setColorMode', 'func': 'set_color_mode', 'persistent': False, 'is_option': False},
    ]
    _frida_cmds = _original_frida_cmds[:]
    _script_params = [
        {'name': 'app_name', "option_name": 'app', 'type': 'string', 'default': '', 'help': 'the name of app'},
        {'name': 'module_name', "option_name": 'module', 'type': 'string', 'default': '', 'help': 'the name of so'},
        {'name': 'class_name', "option_name": 'class', 'type': 'string', 'default': '', 'help': 'the name of class'},
        {'name': 'func_name', "option_name": 'func', 'type': 'string', 'default': '', 'help': 'the name of function'},
        {'name': 'addr', "option_name": 'addr', 'type': 'string', 'default': '',
         'help': 'the address of function in memory'},
        {'name': 'offset', "option_name": 'offset', 'type': 'string', 'default': '0',
         'help': 'the offset to base address'},
        {'name': 'length', "option_name": 'length', 'type': 'string', 'default': '0',
         'help': 'length of the memory to dump or save'},
        {'name': 'deep_search', "option_name": 'deep_search', 'type': 'bool', 'default': False,
         'help': 'enable deep search maybe detected more dex, but speed will be slower'},
    ]
    _is_silence = False
    _show_detail = False

    def __init__(self):
        pass

    @staticmethod
    def set_silence(is_silence):
        Scriptor._is_silence = is_silence

    @staticmethod
    def set_show_detail(show_detail):
        Scriptor._show_detail = show_detail

    @staticmethod
    def get_show_detail():
        return Scriptor._show_detail

    @staticmethod
    def reset_frida_cmds():
        Scriptor._frida_cmds = Scriptor._original_frida_cmds[:]

    @staticmethod
    def add_cmd_options(parser):
        cmd_group = OptionGroup(parser, 'Command Options')
        for item in Scriptor._frida_cmds:
            if "is_option" in item.keys() and item['is_option']:
                cmd_group.add_option("", f"--{item['func']}", action="store_true", dest=f"{item['func']}",
                                     default=False,
                                     help=f'{item["help"]}')
        parser.add_option_group(cmd_group)

    @staticmethod
    def print_cmds_help():
        print('Options:')
        for item in Scriptor._frida_cmds:
            if "is_option" in item.keys() and item['is_option']:
                print(clr_bright_cyan(f"  --{item['func']:<30}") + item['help'])
                print(f"{' ' * 34}{Scriptor._get_cmd_usage(item)}")
        print('\nParameters:')
        for item in Scriptor._script_params:
            print(clr_bright_cyan(f"  --{item['option_name']:<30}") + item['help'])

    @staticmethod
    def add_param_options(parser):
        param_group = OptionGroup(parser, 'Parameter Options')
        for item in Scriptor._script_params:
            if item['type'] == 'string':
                param_group.add_option("", f"--{item['option_name']}", action="store", type="string",
                                       dest=f"{item['name']}", default=f"'{item['default']}'", help=f'{item["help"]}')
            else:
                param_group.add_option("", f"--{item['option_name']}", action="store_true", dest=f"{item['name']}",
                                       default={item['default']}, help=f'{item["help"]}')
        parser.add_option_group(param_group)

    @staticmethod
    def load_scripts():
        script_file = os.path.join(dirname(abspath(__file__)), 'scripts.js')
        with open(script_file, "r", encoding='utf-8') as f:
            return f.read()

    @staticmethod
    def prepare_script(options, imp_mods):
        script = None
        cmd = Scriptor._get_option(options, "cmd")
        if cmd == '' or (cmd != 'custom' and not Scriptor._get_cmd_info(cmd)):
            if cmd != '':
                print(clr_bright_red(f'unknown option, please see {clr_bright_cyan("options")}'))
            return script
        if cmd == 'custom':
            file_script = Scriptor._get_option(options, "file_script")
            if file_script != '':
                key = f'--file_script {file_script}'
                script = {'file_script': file_script, 'cmd': 'custom', 'persistent': True, 'key': key,
                          'isEnable': True, 'apiCmd': '', 'params': None}
            else:
                print(clr_bright_red('custom: --file_script must be set'))
        elif cmd:
            if cmd == 'hook_so_func':
                module = Scriptor._get_option(options, "module", '')
                func = Scriptor._get_option(options, "func", '')
                addr = Scriptor._get_option(options, "addr", '')
                if module != '' and (func != '' or addr != ''):
                    key = f"--{cmd} --module {module} {'--func %s' % func if func != '' else ''}" \
                          + f" {'--addr %s' % addr if addr != '' else ''}"
                    api_cmd = f'self._script.exports.{cmd}("{module}", "{func}", "{addr}")'
                    params = {'module': module, 'func': func, 'addr': addr}
                    script = {'cmd': cmd, 'key': key, 'apiCmd': api_cmd, 'params': params, 'persistent': True}
                else:
                    cmd_def = Scriptor._get_cmd_info(cmd)
                    print(Scriptor._get_cmd_usage(cmd_def))
            else:
                script = Scriptor._gen_script(cmd, options)

            if script:
                script['onMessage'] = Scriptor.on_message
                script['isEnable'] = True

        return script

    @staticmethod
    def gen_script_str(*args):
        if len(args) == 2:
            return Scriptor._gen_script_str_by_map(args[0], args[1])
        elif len(args) == 3:
            return Scriptor._gen_script_str_by_params(args[0], args[1], args[2])
        else:
            raise ArgumentsErrorException('gen_script_str arguments error.')

    @staticmethod
    def _gen_script_str_by_map(scripts_map, imp_mods):
        fun_on_msg = Scriptor.on_message
        scripts_str_ex = ''
        rpc_defines = []
        for key in scripts_map.keys():
            if scripts_map[key]['isEnable']:
                if 'file_script' in scripts_map[key].keys():
                    file_script = scripts_map[key]['file_script']
                    cur_script_str, cur_rpc_define, cur_fun_on_msg = Scriptor.__load_script_file(file_script, imp_mods)
                    if cur_script_str:
                        scripts_str_ex += cur_script_str + '\n'
                        if cur_rpc_define and isinstance(cur_rpc_define, list):
                            rpc_defines += cur_rpc_define
                        if cur_fun_on_msg:
                            fun_on_msg = cur_fun_on_msg
                    else:
                        print(f'Error: jscode not found in {file_script}!')
        scripts_str = Scriptor._merge_script(rpc_defines, scripts_str_ex)
        return scripts_str, fun_on_msg

    @staticmethod
    def _gen_script_str_by_params(script_str, rpc_define, fun_on_msg):
        fun_on_msg = fun_on_msg if fun_on_msg else Scriptor.on_message
        scripts_str = Scriptor._merge_script(rpc_define, script_str)
        return scripts_str, fun_on_msg

    @staticmethod
    def clean_scripts_map(scripts_map):
        _id = 0
        new_map = {}
        for key in scripts_map.keys():
            if scripts_map[key]['persistent']:
                new_map[key] = scripts_map[key]
                new_map[key]["id"] = _id
                _id += 1
        return new_map

    @staticmethod
    def on_message(message, data):
        if message['type'] == 'send':
            msg_data = message['payload']
            if isinstance(msg_data, dict):
                Scriptor._handle_one_message(msg_data)
            elif isinstance(msg_data, list):
                if len(msg_data) > 0 and isinstance(msg_data[0], str):
                    msg_data.sort(key=lambda s: s)
                for msg in msg_data:
                    if isinstance(msg, dict):
                        Scriptor._handle_one_message(msg)
                    else:
                        if not Scriptor._is_silence:
                            print_screen(f'{clr_bright_purple("*")} {msg}', False)
                        write_log(msg)
            else:
                if not Scriptor._is_silence:
                    print_screen(msg_data)
                write_log(msg_data)
        else:
            if not Scriptor._is_silence:
                print_screen(message)
            write_log(message)
        print_prompt()

    @staticmethod
    def get_cmd_usage(cmd):
        cmd_def = Scriptor._get_cmd_info(cmd)
        return Scriptor._get_cmd_usage(cmd_def)

    @staticmethod
    def _handle_one_message(msg_data):
        text_to_print = ''
        _underline = "_" * 20
        if 'type' in msg_data.keys():
            if msg_data['type'] == 'stack':
                timestamp = f"[{str(msg_data['timestamp'])}]" if 'timestamp' in msg_data.keys() else ""
                hook_name = msg_data["funcName"] if 'funcName' in msg_data.keys() else ''
                text_to_print = clr_bright_green(clr_blink(f'{_underline}{"%s %s" % (timestamp, hook_name):^40}'
                                                           + f'{_underline}\n'))
                if Scriptor._show_detail:
                    straces = re.split(',', msg_data['data'].encode('utf8', 'ignore').decode('utf8'))
                    text_to_print = text_to_print + clr_bright_green(f'stack:\n  ') + '\n  '.join(straces)
            elif msg_data['type'] == 'asm_args':
                arg_list = []
                for key in msg_data['data'].keys():
                    arg_list.append(key + '\t' + clr_cyan(str(msg_data['data'][key])))
                text_to_print = clr_bright_green(f'arguments:[{len(arg_list)}]\n  ') + '\n  '.join(arg_list)
            elif msg_data['type'] == 'arguments':
                args_before = json.loads(msg_data['before'])
                args_after = json.loads(msg_data['after'])
                arg_list = []
                for key in args_before.keys():
                    arg_class = f"\t{args_before[key]['class']}" if len(args_before[key]['class']) > 0 else ''
                    if args_before[key]['value'] == args_after[key]['value']:
                        arg_list.append(f'  {key}:{arg_class}\t{clr_yellow(str(args_before[key]["value"]))}')
                    else:
                        arg_list.append(' *' + key + ':' + arg_class + '\n    before: ' \
                                        + clr_yellow(str(args_before[key]["value"])) \
                                        + '\n     after: ' + clr_yellow(str(args_after[key]["value"])))
                    if Scriptor._show_detail and len(args_before[key]['fields'].keys()) > 0:
                        fields_before = args_before[key]['fields']
                        fields_after = args_after[key]['fields']
                        field_list = Scriptor.__prepare_fields_msg(fields_before, fields_after, "    └")
                        arg_list += field_list
                text_to_print = clr_bright_green(f'arguments:[{len(args_before)}]\n') + '\n'.join(arg_list)
            elif msg_data['type'] == 'fields' and Scriptor._show_detail:
                fields_before = json.loads(msg_data['before'])
                fields_after = json.loads(msg_data['after']) if 'after' in msg_data.keys() else fields_before
                field_list = Scriptor.__prepare_fields_msg(fields_before, fields_after)
                class_name = msg_data["class"] + " " if 'class' in msg_data.keys() else ''
                value = msg_data["value"] + " " if 'value' in msg_data.keys() else ''
                text_to_print = clr_bright_green(f'{class_name}fields:[{len(fields_before)}]  {clr_yellow(value)}\n') + '\n'.join(field_list)
            elif msg_data['type'] == 'return':
                if 'funcName' in msg_data.keys():
                    text_to_print = clr_bright_green(clr_blink(f'{_underline}{msg_data["funcName"]:^40}'
                                                               + f'{_underline}\n'))
                ret_class = f"{msg_data['class']}\t" if len(msg_data['class']) > 0 else ''
                text_to_print += clr_bright_green('return:\n') + f'  {ret_class}{clr_yellow(msg_data["value"])}\n'
                field_list = []
                if Scriptor._show_detail and 'fields' in msg_data.keys():
                    fields = json.loads(msg_data['fields'])
                    for key in fields.keys():
                        field_name = fields[key]['field'] if 'field' in fields[key].keys() else key
                        field_info = "    └ field: " + clr_bright_cyan(field_name) + "\tclass: " + fields[key]['class'] \
                                     + "\tvalue: " + clr_bright_purple(str(fields[key]['value']))
                        field_list.append(field_info)
                    text_to_print += '\n'.join(field_list)
            elif msg_data['type'] == 'registerNatives':
                methods = json.loads(msg_data['methods'])
                method_infos = []
                for item in methods:
                    method_infos.append(
                        f'  {clr_bright_cyan(item["module_name"])} {clr_yellow(item["java_class"])} {item["fnPtr"]}'
                        + f' {item["offset"]} {clr_bright_purple(item["name"])} {item["sig"]}')
                text_to_print = '\n'.join(method_infos)
            elif msg_data['type'] == 'request':
                text_to_print = clr_bright_green(f'request:\n') + '\n'.join(parse_request(msg_data))
            elif msg_data['type'] == 'response':
                text_to_print = clr_bright_green(f'response:\n') + '\n'.join(parse_response(msg_data))
        else:
            text_to_print = Scriptor.__get_print_text_for_dict(msg_data)
        if not Scriptor._is_silence:
            print_screen(text_to_print.encode('gbk', 'ignore').decode('gbk'))
        write_log(text_to_print)

    @staticmethod
    def __prepare_fields_msg(fields_before, fields_after, prefix=" "):
        field_list = []
        for key in fields_before.keys():
            field_name = fields_before[key]['field'] if 'field' in fields_before[key].keys() else key
            if fields_before[key]['value'] == fields_after[key]['value']:
                field_info = prefix + " field: " + clr_bright_cyan(field_name) + "\tclass: " + fields_before[key]['class'] \
                             + "\tvalue: " + clr_bright_purple(str(fields_before[key]['value']))
            else:
                field_info = prefix + "*field: " + clr_bright_cyan(field_name) + "\tclass: " + fields_before[key]['class'] \
                             + "\n" + " " * len(prefix) + "  value_before: " + clr_bright_purple(str(fields_before[key]['value'])) \
                             + "\n" + " " * len(prefix) + "  value_after : " + clr_bright_purple(str(fields_after[key]['value']))
            field_list.append(field_info)
        return field_list

    @staticmethod
    def __get_print_text_for_dict(msg_data):
        datas = []
        max_len = 0
        for key in msg_data.keys():
            if len(key) > max_len:
                max_len = len(key)
        for key in msg_data.keys():
            datas.append(f'{clr_yellow(key)}{" " * (max_len - len(key) + 1)}{clr_bright_cyan(msg_data[key])}')
        return '\n'.join(datas)

    @staticmethod
    def __load_script_file(file_script, imp_mods):
        script_str = rpc_define = fun_on_msg = None
        if file_script and file_script != '':
            if file_script in imp_mods.keys():
                mod = imp_mods[file_script]
                importlib.reload(mod)
                print(f'module {clr_cyan(file_script)} was reloaded.')
            else:
                mod = importlib.import_module(file_script)
                if mod:
                    imp_mods[file_script] = mod
                    print(f'module {clr_cyan(file_script)} was loaded.')
                else:
                    print(clr_red(f'module {file_script} failed to load.'))
            if mod:
                if hasattr(mod, "jscode"):
                    script_str = mod.jscode
                if hasattr(mod, "rpc_define"):
                    rpc_define = mod.rpc_define
                if hasattr(mod, "on_message"):
                    fun_on_msg = mod.on_message
        return script_str, rpc_define, fun_on_msg

    @staticmethod
    def _get_option(options, item, default=''):
        if isinstance(options, dict):
            if 'cf' in options.keys() and options['cf'].has_option(options['section'], item):
                return options['cf'].get(options['section'], item)
            elif 'cmd' in options.keys() and item in options.keys():
                return options[item]
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
                    print(clr_bright_red(f'invalidate parameter: {cmd[1]}'))
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
            for item in Scriptor._frida_cmds:
                if "is_option" in item.keys() and item['is_option'] and getattr(options, item['func']):
                    return item['func']
            if options.file_script:
                ret = 'custom'
        else:
            try:
                ret = getattr(options, item) if getattr(options, item) else default
            except:
                ret = default
        return ret

    @staticmethod
    def _get_cmd_info(cmd):
        for info in Scriptor._frida_cmds:
            if info['func'] == cmd:
                return info
        return None

    @staticmethod
    def _gen_script(cmd, options):
        script = None
        cmd_def = Scriptor._get_cmd_info(cmd)
        if 'params' in cmd_def.keys() and len(cmd_def['params']) > 0:
            params = {}
            params_in_key = []
            params_in_api = []
            is_param_ok = True
            for param_def in cmd_def['params']:
                name = param_def['name']
                type = param_def['type']
                value = Scriptor._get_option(options, name, '')
                if value != '' or ('isOptional' in param_def.keys() and param_def['isOptional']):
                    params[name] = value
                    params_in_key.append(f'--{name} {value}')
                    param_in_api = f'"{value}"' if type == "string" else value
                    params_in_api.append(param_in_api)
                else:
                    is_param_ok = False
                    break
            if is_param_ok:
                key = f"--{cmd} {' '.join(params_in_key)}"
                api_cmd = f'self._script.exports.{cmd}({", ".join(params_in_api)})'
                persistent = cmd_def['persistent'] if 'persistent' in cmd_def.keys() else False
                script = {'cmd': cmd, 'key': key, 'apiCmd': api_cmd, 'params': params, 'persistent': persistent}
            else:
                print(clr_bright_red(f'syntax error!\n{Scriptor._get_cmd_usage(cmd_def)}'))
        else:
            key = f"--{cmd}"
            api_cmd = f'self._script.exports.{cmd}()'
            persistent = cmd_def['persistent'] if 'persistent' in cmd_def.keys() else False
            script = {'cmd': cmd, 'key': key, 'apiCmd': api_cmd, 'params': None, 'persistent': persistent}
        return script

    @staticmethod
    def _get_cmd_usage(cmd_def):
        if 'usage' in cmd_def.keys():
            return cmd_def['usage']
        else:
            param_in_usage = []
            if 'params' in cmd_def.keys() and len(cmd_def['params']) > 0:
                for param_def in cmd_def['params']:
                    if 'isOptional' in param_def.keys() and param_def['isOptional']:
                        param_in_usage.append(
                            clr_yellow(f"[--{param_def['name']}") + clr_bright_purple(f" <{param_def['name']}>") + "]")
                    else:
                        param_in_usage.append(
                            clr_yellow(f"--{param_def['name']}") + clr_bright_purple(f" <{param_def['name']}>"))
            return f'Usage: {clr_bright_green("run")} {clr_bright_cyan("--" + cmd_def["func"])}' \
                   + f' {" ".join(param_in_usage)}'

    @staticmethod
    def _merge_script(rpc_defines, script_str_ex):
        Scriptor._frida_cmds = Scriptor._original_frida_cmds + rpc_defines
        rpc_exports = []
        for item in Scriptor._frida_cmds:
            if "api" in item.keys():
                rpc_exports.append(f'    {item["api"]}: {item["func"]},')
        export_script = 'rpc.exports = {\n' + '\n'.join(rpc_exports) + '\n}\n\n'
        return export_script + _script_core + script_str_ex


_script_core = Scriptor.load_scripts()
