from capstone import *
from pwn import *
import os


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[1;32m'
    WARNING = '\033[93m'
    FAIL = '\033[1;31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    FAIL_FLAG = '\x1b[1;37;41m'
    SUCCESS_FLAG = '\x1b[1;37;42m'
    DEFAULT = '\x1b[0m'

    DELTA = '\x1b[2;33m'

def private_asm(code, arch='x86_64', bits=64, base=0x0) :
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print(bcolors.DELTA)
    print("ADDR:\tMNE\tOPR")
    code = tmp(code, arch=arch, bits=bits)
    for i in md.disasm(code, 0):
        print("0x%x:\t%s\t%s" %(i.address + base, i.mnemonic, i.op_str))
    print(bcolors.DEFAULT)
    return code

global asm
tmp = asm
del asm
asm = private_asm

log_level='DEBUG'
context.arch = 'x86_64'
context.bits = 64


def debug(string : str, end : str ='\n') :
    print(bcolors.OKGREEN + str(string) + bcolors.DEFAULT, end=end)

def dummy(string : str, end: str = '\n') :
    return

if not(os.getenv('DEBUG') and os.getenv('DEBUG').lower() == 'yes') :
    del debug
    debug = dummy
    del asm
    asm = tmp
