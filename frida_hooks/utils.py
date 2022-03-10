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


def exec_cmd(cmd, timeout_in_sec=0, is_show_msg=False):
    if is_show_msg:
        print(f'execute: "{cmd}"')
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
    pname = pname.lower()
    lines = re.split('\r\n', text)
    for line in lines:
        tokens = re.split(' ', line)
        filtered_tokens = []
        for t in tokens:
            if len(t) != 0:
                filtered_tokens.append(t)
        if len(filtered_tokens) == 9 and filtered_tokens[8].lower() == pname and is_number(filtered_tokens[1]):
            return int(filtered_tokens[1])
    return 0


def __get_proc_name_in_text(text, pid):
    lines = re.split('\r\n', text)
    for line in lines:
        tokens = re.split(' ', line)
        filtered_tokens = []
        for t in tokens:
            if len(t) != 0:
                filtered_tokens.append(t)
        if len(filtered_tokens) == 9 and is_number(filtered_tokens[1]) and int(filtered_tokens[1]) == pid:
            return filtered_tokens[8]
    return None


def get_pid_by_adb_shell(device_id, name, wait_time_in_sec=1):
    pid = 0
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


def get_proc_name_by_pid(device_id, pid, wait_time_in_sec=1):
    proc_name = None
    for i in range(wait_time_in_sec):
        cmd = f"adb -s {device_id} shell ps"
        ret = exec_cmd(cmd, 2)
        if ret is None:
            print("请重新拔插手机上的usb线")
            sys.exit(-1)

        proc_name = __get_proc_name_in_text(ret, pid)
        if proc_name:
            break
        time.sleep(1)
    return proc_name


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


def get_host(device_id):
    cmd = f'adb -s {device_id} shell "netcfg | grep wlan0"'
    ret = exec_cmd(cmd, 2, False)
    if ret is None:
        return ""
    matches = re.search(r"([\d]+\.[\d]+\.[\d]+\.[\d]+)", ret)
    if matches is not None:
        return matches.group(1)
    else:
        return ""


def write_log(text):
    if isinstance(text, str):
        for key in ansi_colors.keys():
            text = text.replace(ansi_colors[key], '')
        logger.info(text)


def set_exit_handler(sig, func):
    signal.signal(sig, func)


def list_device_by_adb():
    devices = []
    cmd = "adb devices -l"
    ret = exec_cmd(cmd, 10)
    if ret:
        lines = re.split('\r\n', ret)
        new_lines = [i for i in lines if i != '']
        for line in new_lines[1:]:
            parts = re.split(' ', line)
            new_parts = [i for i in parts if i != '']
            devices.append({"id": new_parts[0], "status": new_parts[1], "name": new_parts[2].split(":")[1]})
    return devices


def reconnect_offline_devices(devices=None):
    devices = list_device_by_adb() if devices is None else devices
    for dev_info in devices:
        if dev_info["status"] != 'device':
            try:
                cmd = f'adb -s {dev_info["id"]} reconnect offline"'
                ret = exec_cmd(cmd, 5)
                print(f'{cmd}\n{ret}')
            except Exception as e:
                print(e)


def kill_process(device_id, pid, force=True):
    if pid > 0:
        su_str = " " if len(device_id.split('.')) == 4 else " su -c "
        sig = ' -9 ' if force else ' '
        cmd = f'adb -s {device_id} shell{su_str}"kill{sig}{pid}"'
        ret = exec_cmd(cmd, 10)
        print(f'{cmd}\n{ret}')

