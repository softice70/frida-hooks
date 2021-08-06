import optparse
import random
import click
from shutil import get_terminal_size as get_terminal_size
from frida_hooks.utils import *
from frida_hooks.agent import FridaAgent


banner = """
███████╗██████╗ ██╗██████╗  █████╗     ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗███████╗
██╔════╝██╔══██╗██║██╔══██╗██╔══██╗    ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝██╔════╝
█████╗  ██████╔╝██║██║  ██║███████║    ███████║██║   ██║██║   ██║█████╔╝ ███████╗
██╔══╝  ██╔══██╗██║██║  ██║██╔══██║    ██╔══██║██║   ██║██║   ██║██╔═██╗ ╚════██║
██║     ██║  ██║██║██████╔╝██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗███████║
╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝
                              [v0.9] by Ryan
            url: https://github.com/softice70/frida-hooks            
"""


screen_cols = get_terminal_size().columns
agent = None


def show_banner(is_random_color=False):
    colors = ['bright_red', 'bright_green', 'bright_blue', 'cyan', 'magenta']
    try:
        click.style('color test', fg='bright_red')
    except:
        colors = ['red', 'green', 'blue', 'cyan', 'magenta']
    try:
        columns = get_terminal_size().columns
        if columns >= len(banner.splitlines()[1]):
            for line in banner.splitlines():
                if line:
                    fill = int((columns - len(line)) / 2)
                    line = line[0] * fill + line
                    line += line[-1] * fill
                cur_color = random.choice(colors) if is_random_color else 'bright_green'
                click.secho(line, fg=cur_color)
    except:
        pass


def on_exit(sig, stack):
    if sig == signal.SIGINT or sig == signal.SIGTERM:
        global agent
        agent.exit()


def main():
    global agent
    click.secho(banner, fg='bright_green')
    # 命令行解析
    usage = 'usage: %program [options] [pid|package|app_name]'
    parser = optparse.OptionParser(usage, version="%program 0.9.0")

    signal.signal(signal.SIGINT, on_exit)
    signal.signal(signal.SIGTERM, on_exit)

    agent = FridaAgent(parser)
    agent.run()
    sys.exit(0)


if __name__ == "__main__":
    main()
