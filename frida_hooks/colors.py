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


class Colors:
    hooked = f'{ansi_colors["yellow"]}{ansi_colors["blink"]}'
    keyword = f'{ansi_colors["yellow"]}'
    keyword2 = f'{ansi_colors["bright_purple"]}'
    keyword3 = f'{ansi_colors["bright_cyan"]}'
    path = f'{ansi_colors["bright_blue"]}{ansi_colors["underline"]}'
    title = f'{ansi_colors["bright_green"]}'
    column = f'{ansi_colors["bright_gray"]}{ansi_colors["reverse"]}'
    warning = f'{ansi_colors["bright_red"]}'
    exit = f'{ansi_colors["bright_gray"]}{ansi_colors["reverse"]}'
    reset = ansi_colors["reset"]

    @staticmethod
    def set_monochrome_mode():
        Colors.hooked = Colors.keyword = Colors.keyword2 = Colors.keyword3 = Colors.path \
            = Colors.title = Colors.column = Colors.warning = Colors.exit = Colors.reset = ""
