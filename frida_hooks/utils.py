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
        print(text.encode('gbk', 'ignore').decode('gbk'))
    elif isinstance(text, bytes):
        print(text.decode("gbk", "ignore"))
    else:
        print(text)
    if is_show_prompt:
        print_prompt()


def print_prompt():
    sys.stdout.write(f'\r> ')


def exec_cmd(cmd, timeout_in_sec):
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
    if pRet != 0:
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


def init_logger(log_file):
    if log_file != '':
        logger.setLevel(logging.INFO)
        # create file handler which logs even debug messages
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s  %(name)s  %(levelname)s  %(message)s")
        fh.setFormatter(formatter)
        # add the handlers to logger
        logger.addHandler(fh)


def write_log(text):
    if isinstance(text, str):
        text = text.replace(Colors.hooked, '') \
            .replace(Colors.keyword, '') \
            .replace(Colors.keyword2, '') \
            .replace(Colors.keyword3, '') \
            .replace(Colors.path, '') \
            .replace(Colors.title, '') \
            .replace(Colors.column, '') \
            .replace(Colors.warning, '') \
            .replace(Colors.exit, '') \
            .replace(Colors.reset, '')
        logger.info(text)


def set_exit_handler(sig, func):
    signal.signal(sig, func)



