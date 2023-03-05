import sys
from colorama import init
init()


def pr_red(skk): print("\033[31m{}\033[00m".format(skk))


def pr_green(skk): print("\033[32m{}\033[00m".format(skk))


def pr_yellow(skk): print("\033[93m{}\033[00m".format(skk))


def wr_red(skk): sys.stdout.write("\033[91m{}\033[00m".format(skk)) and wr_flush()


def wr_red_white(skk): sys.stdout.write("\033[91m\033[47m{}\033[00m".format(skk)) and wr_flush()


def wr_green(skk): sys.stdout.write("\033[32m{}\033[00m".format(skk)) and wr_flush()


def wr_yellow(skk): sys.stdout.write("\033[93m{}\033[00m".format(skk)) and wr_flush()


def wr_purple(skk): sys.stdout.write("\033[95m{}\033[00m".format(skk)) and wr_flush()


def wr_line(): wr_purple("------------------------------------\n")


def wr_flush(): sys.stdout.flush()
