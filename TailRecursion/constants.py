import numpy as np

LONG_LEN = 8
CTR = 0

# HI and LO control the range of test input with implied meanings.
# NUM_INPUTS is the number of test cases.
LO = 14
HI = 30
NUM_INPUTS = 10
#LO = 5
#HI = 10
#NUM_INPUTS = HI - LO + 1

mu = None
hooks = []
allowed_registers = set(['rdi', 'rax', 'rbp', 'rsp'])
# call to only fib function are also allowed
filter_list = ['int3', 'int', 'nop', 'mov', 'add', 'sub', 'xor', 'and', 'or', 'shl', 'shr', 'push', 'pop']
sandbox = False
samples = []
samples_out = []

PAGE_SIZE = 0x1000
STACK_SIZE = 0x80
#STACK_SIZE = 0x8000
BASE_STACK = 0x7FFF80000000 | (np.random.randint(0,0x7FFFF) << 12)
STACK_LIMIT = BASE_STACK - STACK_SIZE
STACK_PAGE  = BASE_STACK - int(PAGE_SIZE * np.ceil(STACK_SIZE/PAGE_SIZE))
CHALL_BASE = 0x69420000 
BASE_ADDR  = np.random.randint(0xFFF,0xFFFF) * PAGE_SIZE

target = 'fib'
ins_string =";# <insert> your code here!"
template = 'template.S'
fib_file = 'fib.S'
string_regex = r'[^a-zA-Z0-9]([a-zA-Z][a-zA-Z0-9]+)' 
INT7_trav = False

restricted = ['real10', 'real8', 'real4', 'tbyte', 'qword', 'fword', 'dword', 'sdword', 'word', 'sword', 'byte', 'sbyte', 'ptr']
shadow_stack = []

END_MARKER = '$'
