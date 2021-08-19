#! /usr/bin/python
# -*-coding: UTF-8 -*-


import sys
import platform
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


def exec_cmd(cmd, timeout_in_sec=0, is_show_msg=True):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

    def kill_process():
        try:
            p.kill()
        except OSError:
            pass  # Swallow the error

    if timeout_in_sec > 0:
        timer = Timer(timeout_in_sec, kill_process)
        timer.start()
    ret, err = p.communicate()
    pRet = p.wait()
    if timeout_in_sec > 0:
        timer.cancel()
    if pRet != 0 and is_show_msg:
        print(f'execute: "{cmd}" timeout')
    console_code_page = "gbk" if platform.system().lower() == 'windows' else "utf-8"
    ret = ret.decode(console_code_page, "ignore") if ret else ret
    return ret


def is_number(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def __get_pid_in_text(text, pname):
    lines = re.split('\r\n', text)
    for line in lines:
        tokens = re.split(' ', line)
        filtered_tokens = []
        for t in tokens:
            if len(t) != 0:
                filtered_tokens.append(t)
        if len(filtered_tokens) == 9 and filtered_tokens[8] == pname and is_number(filtered_tokens[1]):
            return int(filtered_tokens[1])
    return -1


def get_pid_by_adb_shell(device_id, name, wait_time_in_sec=1):
    pid = -1
    for i in range(wait_time_in_sec):
        cmd = f"adb -s {device_id} shell ps"
        ret = exec_cmd(cmd, 2)
        if ret is None:
            print("请重新拔插手机上的usb线")
            sys.exit(-1)

        pid = __get_pid_in_text(ret, name)
        if pid > 0:
            return pid
        time.sleep(1)
    return pid


def get_app_version(device_id, name):
    cmd = f'adb -s {device_id} shell "dumpsys package {name} | grep versionName"'
    ret = exec_cmd(cmd, 2, False)
    if ret is None:
        return ""
    tokens = re.split('=', ret.strip())
    if len(tokens) == 2 and tokens[0] == 'versionName':
        return tokens[1]
    else:
        return ""


def write_log(text):
    if isinstance(text, str):
        for key in ansi_colors.keys():
            text = text.replace(ansi_colors[key], '')
        logger.info(text)


def set_exit_handler(sig, func):
    signal.signal(sig, func)


