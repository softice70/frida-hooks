#! /usr/bin/python
# -*-coding: UTF-8 -*-


ansi_colors = {
    "reset": "\033[0m",
    "black": "\033[0;30m",
    "dark_gray": "\033[1;30m",
    "blue": "\033[0;34m",
    "bright_blue": "\033[1;34m",
    "green": "\033[0;32m",
    "bright_green": "\033[1;32m",
    "cyan": "\033[0;36m",
    "bright_cyan": "\033[1;36m",
    "red": "\033[0;31m",
    "bright_red": "\033[1;31m",
    "purple": "\033[0;35m",
    "bright_purple": "\033[1;35m",
    "brown": "\033[0;33m",
    "yellow": "\033[1;33m",
    "bright_gray": "\033[0;37m",
    "white": "\033[1;37m",
    "bg_black": "\033[40m",
    "bg_red": "\033[41m",
    "bg_green": "\033[42m",
    "bg_yellow": "\033[43m",
    "bg_blue": "\033[44m",
    "bg_purple": "\033[45m",
    "bg_cyan": "\033[46m",
    "bg_white": "\033[47m",
    "bright": "\033[1m",
    "dim": "\033[2m",
    "underline": "\033[4m",
    "blink": "\033[5m",
    "reverse": "\033[7m",
    "strikethrough": "\033[9m",
    "overline": "\033[53m",
}

_is_color_mode = True
clr_reset = lambda: "\033[0m" if _is_color_mode else ''
clr_black = lambda text: clr_ansify("\033[0;30m", text)
clr_dark_gray = lambda text: clr_ansify("\033[1;30m", text)
clr_blue = lambda text: clr_ansify("\033[0;34m", text)
clr_bright_blue = lambda text: clr_ansify("\033[1;34m", text)
clr_green = lambda text: clr_ansify("\033[0;32m", text)
clr_bright_green = lambda text: clr_ansify("\033[1;32m", text)
clr_cyan = lambda text: clr_ansify("\033[0;36m", text)
clr_bright_cyan = lambda text: clr_ansify("\033[1;36m", text)
clr_red = lambda text: clr_ansify("\033[0;31m", text)
clr_bright_red = lambda text: clr_ansify("\033[1;31m", text)
clr_purple = lambda text: clr_ansify("\033[0;35m", text)
clr_bright_purple = lambda text: clr_ansify("\033[1;35m", text)
clr_brown = lambda text: clr_ansify("\033[0;33m", text)
clr_yellow = lambda text: clr_ansify("\033[1;33m", text)
clr_bright_gray = lambda text: clr_ansify("\033[0;37m", text)
clr_white = lambda text: clr_ansify("\033[1;37m", text)
clr_bg_black = lambda text: clr_ansify("\033[40m", text)
clr_bg_red = lambda text: clr_ansify("\033[41m", text)
clr_bg_green = lambda text: clr_ansify("\033[42m", text)
clr_bg_yellow = lambda text: clr_ansify("\033[43m", text)
clr_bg_blue = lambda text: clr_ansify("\033[44m", text)
clr_bg_purple = lambda text: clr_ansify("\033[45m", text)
clr_bg_cyan = lambda text: clr_ansify("\033[46m", text)
clr_bg_white = lambda text: clr_ansify("\033[47m", text)
clr_bright = lambda text: clr_ansify("\033[1m", text)
clr_dim = lambda text: clr_ansify("\033[2m", text)
clr_underline = lambda text: clr_ansify("\033[4m", text)
clr_blink = lambda text: clr_ansify("\033[5m", text)
clr_reverse = lambda text: clr_ansify("\033[7m", text)
clr_strikethrough = lambda text: clr_ansify("\033[9m", text)
clr_overline = lambda text: clr_ansify("\033[53m", text)

clr_ansify = lambda color, text: f'{color}{text}\033[0m' if _is_color_mode else text


def set_color_mode(is_color_mode):
    global _is_color_mode
    _is_color_mode = is_color_mode


def get_color_mode():
    global _is_color_mode
    return _is_color_mode

