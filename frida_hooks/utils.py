#! /usr/bin/python
# -*-coding: UTF-8 -*-


import sys
import subprocess
from threading import Timer
import re
import time
import logging
import signal
from frida_hooks.colors import *


logger = logging.getLogger()


def print_screen(text, is_show_prompt=True):
    if isinstance(text, str):
        print(f"\r{text.encode('gbk', 'ignore').decode('gbk')}")
    elif isinstance(text, bytes):
        print(text.decode("gbk", "ignore"))
    else:
        print(text)
    if is_show_prompt:
        print_prompt()


def print_prompt():
    sys.stdout.write(f'\r> ')


def exec_cmd(cmd, timeout_in_sec, is_show_msg=True):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

    def kill_process():
        try:
            p.kill()
        except OSError:
            pass  # Swallow the error

    timer = Timer(timeout_in_sec, kill_process)
    timer.start()
    ret, err = p.communicate()
    pRet = p.wait()
    timer.cancel()
    if pRet != 0 and is_show_msg:
        print(f'execute: "{cmd}" timeout')
    return ret


def is_number(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def __get_pid_in_text(text, pname):
    lines = re.split('\r\n', text.decode("gbk", 'ignore'))
    for line in lines:
        tokens = re.split(' ', line)
        filtered_tokens = []
        for t in tokens:
            if len(t) != 0:
                filtered_tokens.append(t)
        if len(filtered_tokens) == 9 and filtered_tokens[8] == pname and is_number(filtered_tokens[1]):
            return int(filtered_tokens[1])
    return -1


def get_pid_by_adb_shell(name, wait_time_in_sec=1):
    pid = -1
    for i in range(wait_time_in_sec):
        cmd = "adb shell ps"
        ret = exec_cmd(cmd, 2)
        if ret is None:
            print("请重新拔插手机上的usb线")
            sys.exit(-1)

        pid = __get_pid_in_text(ret, name)
        if pid > 0:
            return pid
        time.sleep(1)
    return pid


def get_app_version(name):
    cmd = f'adb shell "dumpsys package {name} | grep versionName"'
    ret = exec_cmd(cmd, 2, False)
    if ret is None:
        return "Unknown"
    tokens = re.split('=', ret.decode("gbk", 'ignore').strip())
    if len(tokens) == 2 and tokens[0] == 'versionName':
        return tokens[1]
    else:
        return "Unknown"


def write_log(text):
    if isinstance(text, str):
        for key in ansi_colors.keys():
            text = text.replace(ansi_colors[key], '')
        logger.info(text)


def set_exit_handler(sig, func):
    signal.signal(sig, func)


def parse_request(data):
    param_infos = []
    for key in ['method', 'url', 'headers', 'body', 'class', 'request', 'probe']:
        if key in data.keys():
            if key != 'headers':
                if len(data[key]) > 0:
                    param = f'  {clr_bright_cyan(key)}: {data[key].strip()}'
                else:
                    continue
            else:
                headers = data['headers'].strip().replace("\n", ", ")
                param = f'  {clr_bright_cyan("headers")}: {headers}'
            param_infos.append(param)
    return param_infos


def parse_response(data):
    response = data['response'].strip()[9:-1]
    param_infos = []
    while len(response) > 0:
        param, response = __get_param_from_request(response)
        param_infos.append(param)
    for key in ['headers', 'body', 'class', 'response']:
        if key in data.keys():
            if key != 'headers':
                if len(data[key]) > 0:
                    param = f'  {clr_bright_cyan(key)}: {data[key].strip()}'
                else:
                    continue
            else:
                headers = data['headers'].strip().replace("\n", ", ")
                param = f'  {clr_bright_cyan("headers")}: {headers}'
            param_infos.append(param)
    return param_infos


def __get_param_from_request(request):
    key, request = __get_key_from_request(request)
    value, request = __get_value_from_request(request)
    param = f'  {clr_bright_cyan(key)}: {value}'
    return param, request


def __get_key_from_request(request):
    idx = request.find("=")
    key = request[:idx]
    request = request[idx + 1:]
    return key, request


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


