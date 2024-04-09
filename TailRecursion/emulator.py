from unicorn import *
from unicorn.x86_const import *
from capstone import *
from pwn import *

import numpy as np
import struct
import re

from debug import *
from constants import *

REG_MAP = {
    "rax": UC_X86_REG_RAX,
    "rdi": UC_X86_REG_RDI,
    "rip": UC_X86_REG_RIP,
    "rbp": UC_X86_REG_RBP,
    "rsp": UC_X86_REG_RSP,
}
len_call = len(asm("call test; test:"))

def eliminate (reg: str) :
    return (reg not in restricted)


def fibonacci(n: int) :
    """
    calculates the fibonacci of an integer n
    fibonacci series : { 1:1, 2:1, 3:2, 4:3, 5:5, 6:8, 7:13, ...}
    """
    a_0 = 0
    a_1 = 1
    for _ in range(0,n):
        a_0 += a_1
        a_0 = a_0 ^ a_1
        a_1 = a_0 ^ a_1
        a_0 = a_0 ^ a_1
    return a_0

def check_stack(uc, address, size, i) :
    global shadow_stack
    diff = BASE_STACK - uc.reg_read(UC_X86_REG_RSP) 
    debug("\n\n")
    debug(f"BASE STACK DIFF: {diff}")
    debug(f"executing: {i.mnemonic} {i.op_str}")
    curr = uc.reg_read(UC_X86_REG_RSP) 
    debug("STATE")
    ctr = 0
    debug(f"RIP: {hex(uc.reg_read(UC_X86_REG_RIP))}")
    debug(f"RAX: {hex(uc.reg_read(UC_X86_REG_RAX))}")
    debug(f"RDI: {hex(uc.reg_read(UC_X86_REG_RDI))}")
    debug(f"RBP: {hex(uc.reg_read(UC_X86_REG_RBP))}")
    debug(f"RSP: {hex(uc.reg_read(UC_X86_REG_RSP))}")
    debug(f"Shadow Stack : {list(map(hex, shadow_stack))}")
    while ctr < diff : 
        if ctr % 32 == 0 :
            debug("")
            debug(hex(curr), end=": ")
        tmp = uc.mem_read(curr, LONG_LEN)
        #tmp = b''.join([bytes(chr(tmp[i]), encoding='latin1') for i in range(0,8)])
        #debug(hex(struct.unpack('<Q',tmp))[2:], end=" ")
        debug(''.join(reversed([hex(ord(chr(tmp[i])))[2:] for i in range(8)])), end=" ")
        ctr += LONG_LEN
        curr += LONG_LEN

    debug("")

    if diff > STACK_SIZE or diff < 0 :
        emu_err = "fail: Stay in your stack, you filthy swine! rsp 0x%x" % uc.reg_read(UC_X86_REG_RSP)
        print("fail: Stay in your stack, you filthy swine! rsp: 0x%x" % uc.reg_read(UC_X86_REG_RSP))
        uc.emu_stop()
        return
    uc.mem_write(STACK_PAGE, b'\x00' * (STACK_LIMIT - STACK_PAGE))
    return

def whitelist_hook(uc, address, size, user_data):
    global shadow_stack
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    i = next(md.disasm(uc.mem_read(address, size), address))

    check_stack(uc, address, size, i)

    if i.mnemonic.lower() == 'call' :
        if int(i.op_str.strip()[2:], 16) - BASE_ADDR == fib_offset :
            shadow_stack += [uc.reg_read(UC_X86_REG_RIP) + len_call]
            return

    if i.mnemonic.lower() == 'ret' :
        if address == ret_offset + BASE_ADDR :
            shadow_stack = shadow_stack[:-1]
            return

    if i.mnemonic.lower() not in filter_list:
        emu_err = "fail: this instruction is on vacation: %s" % i.mnemonic
        print("fail: this instruction is on vacation: %s %s" % (i.mnemonic, i.op_str))
        uc.emu_stop()
        return

    tokens = set(filter(lambda x: eliminate(x.lower()), re.findall(string_regex, i.op_str)))
    if len(tokens - allowed_registers) :
        debug(tokens)
        debug(i.op_str)
        emu_err = "fail: registers except rax, rbp and rsp are on strike and no directives please."
        print("fail: registers except rax, rbp and rsp are on strike and no directives please.")
        uc.emu_stop()
        return

def INT7_hook(uc, address, size, user_data):
    global shadow_stack
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    i = next(md.disasm(uc.mem_read(address, size), address))

    check_stack(uc, address, size, i)

    if i.mnemonic.lower() == 'ret':
        shadow_stack = shadow_stack[:-1]
    handle_INT(uc, 3, None)
    return
    

def handle_INT(uc, intno, user_data) :
    global sandbox, hooks, CTR, fib_offset, BASE_ADDR
    debug(f"Interrupt Number: {intno}")

    # puts the program into a sandbox!
    if intno == 3:
        debug( ("" if sandbox else "NO ") + "Sandbox")
        debug("Warning: Sandbox Engaged")
        if not sandbox:
            for hook in hooks :
                uc.hook_del(hook)
            hooks = [uc.hook_add(UC_HOOK_CODE, whitelist_hook)]
            sandbox = not(sandbox)
        #uc.reg_write(UC_X86_REG_RIP, uc.reg_read(UC_X86_REG_RIP) + 1)
        return

    # Checks if the output in RAX is valid for current challenge 
    # Removes the sandbox if RCX == 0
    if intno == 4:

        curr = NUM_INPUTS - uc.reg_read(UC_X86_REG_RCX)
        val = uc.reg_read(UC_X86_REG_RAX)

        if CTR < NUM_INPUTS :
            if val == samples_out[curr] :
                CTR += 1
                uc.reg_write(UC_X86_REG_RCX, uc.reg_read(UC_X86_REG_RCX) - 1)
            else:
                emu_err = "fail: Wrong answer? interesting... get'em out of 'ere!"
                print("fail: Wrong answer? interesting... get'em out of 'ere!")
                uc.emu_stop()
                debug(f"QUERY         : {samples[curr]}")
                debug(f"VALUE         : {val}")
                debug(f"ACTUAL OUTPUT : {samples_out[curr]}")
                return

        debug(f"CTR: {CTR}")

        if sandbox and CTR >= NUM_INPUTS :
            for hook in hooks :
                uc.hook_del(hook)
            hooks = []
            sandbox = not(sandbox)

        if CTR < NUM_INPUTS :
        #uc.reg_write(UC_X86_REG_RIP, uc.reg_read(UC_X86_REG_RIP) + 2)
            debug(f"QUERY         : {samples[curr]}")
            debug(f"VALUE         : {val}")
            debug(f"ACTUAL OUTPUT : {samples_out[curr]}")
        return

    # puts the input value in the register RAX
    if intno == 5 :
        uc.reg_write(UC_X86_REG_RDI, samples[CTR])
        #uc.reg_write(UC_X86_REG_RIP, uc.reg_read(UC_X86_REG_RIP) + 2)
        return

    # handles the base case for the fib function
    # Oh! Self modifying code! Faannncyy...
    # I wonder what this can do!
    if intno == 7 :
        debug( ("" if sandbox else "NO ") + "Sandbox")
        v = uc.reg_read(UC_X86_REG_RDI)
        rip = uc.reg_read(UC_X86_REG_RIP) 
        stack_ptr = uc.reg_read(UC_X86_REG_RSP)
        if rip == fib_offset + BASE_ADDR + len(asm('int 7')):
            debug("Sandbox Lifted!")
            for hook in hooks :
                uc.hook_del(hook)
            hooks = [uc.hook_add(UC_HOOK_CODE, INT7_hook)]
            sandbox = not(sandbox)

            debug(f"""
:: 
    {hex(struct.unpack('>Q', uc.mem_read(rip , LONG_LEN))[0])} 
    {hex(struct.unpack('>Q', uc.mem_read(rip + LONG_LEN, LONG_LEN))[0])} 
::
            """)

        #uc.reg_write(UC_X86_REG_RAX, struct.unpack("<Q", uc.mem_read(stack_ptr, LONG_LEN))[0])

        ret = None
        if v <= 2 :
            ret = uc.mem_read(stack_ptr, LONG_LEN)
            ret = struct.unpack("<Q", ret)[0]
            uc.reg_write(UC_X86_REG_RAX, 1)
            if shadow_stack[-1] != ret :
                print(f"Liar! Liar! Pants on fire! Trying to return to {hex(ret)}.")
                print(f"But I remember you called from {hex(shadow_stack[-1])}")
                uc.emu_stop()
                return
        else:
            ret = rip + len(asm(f"ret"))
            uc.reg_write(UC_X86_REG_RIP, ret)


        """

        debug("RETURN: "+ hex(ret))
        patch = asm(f"mov r10, {ret}", arch='x86_64', bits=64)
        uc.mem_write(rip, patch)
        debug(f"INT 7    : {list(map(lambda x : hex(x), list(asm('int 7'))))}")
        debug(f"BYTES    : {list(map(lambda x : hex(x), list(uc.mem_read(rip-2, 20))))}")
        debug(f"COMPILED : {list(map(lambda x : hex(x), list(patch)))}")
        uc.reg_write(UC_X86_REG_R10, ret)
        """
        debug(f"""
:: 
    {hex(struct.unpack('>Q', uc.mem_read(rip , LONG_LEN))[0])} 
    {hex(struct.unpack('>Q', uc.mem_read(rip + LONG_LEN, LONG_LEN))[0])} 
::
        """)
        return
    """
    # calls the fib function
    if intno == 7 :
        uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) - 0x8)
        packed = uc.reg_read(UC_X86_REG_RIP) + 2
        uc.reg_write(UC_X86_REG_RIP, BASE_ADDR + fib_offset)
        packed = struct.pack('Q', packed)
        print(packed)
        uc.mem_write(uc.reg_read(UC_X86_REG_RSP), packed) 
        #check_stack(uc)
        print(f"The address of jump: {hex(BASE_ADDR + fib_offset)}")
        return
    """

    if intno == 42:
        if CTR >= NUM_INPUTS :
            print()
            print("Ah... I see, you're now worthy of knowing the ancient wisdom of the Black Knight.")
            print("You seem to refer to it as the flag I reckon: %s" % (os.getenv('FLAG')))
            print()
            print("Godspeed my friend! Stay safe. See you at the court of Camelot!")
            print()
            uc.emu_stop()
            return

    print("Something is Fuck... Ah shit! Here we go again!.")
    print("The interrupt number: %d" % intno)
    uc.emu_stop()
    return

if __name__=='__main__' :
    global fib_offset, ret_offset, exit_offset
    #print(fibonacci(HI))
    #print(fibonacci(LO))
    #print((2<<64)-1)
    #exit(42)

    # submission
    if len(sys.argv) >= 2 :
        if sys.argv[1] == '-':
            fib_code = ''
            while True:
                x = input()
                if (x.strip() == END_MARKER):
                    break
                fib_code += x
        else:
            f = open(sys.argv[1], 'r')
            fib_code = f.read()
            f.close()
    else:
        f = open(fib_file, 'r')
        fib_code = f.read()
        f.close()

        # setup
    f = open(template, 'r')
    code = f.read()
    f.close()

    code = re.sub(r'@NUM_INPUTS', str(NUM_INPUTS), code)
    
    #print(fib_code)

    # get offsets
    fib_offset = len(asm(code.split("fib:")[0] + "\nfib:\ntester:\nexit:", arch='x86_64', bits=64))
    code = code.split(ins_string)
    code[0] += '\n' + fib_code + '\n'
    ret_offset = len(asm(code[0] + "\ntester:", arch='x86_64', bits=64))
    code = code[0] + code[1]
    exit_offset = len(asm(code.split("exit:")[0] + "\nexit:", arch='x86_64', bits=64))
    code = asm(code, arch='x86_64', bits=64)

    #exit(9)

    # test cases
    np.random.seed(ord(os.urandom(1)) & 0x1F)
    samples = np.random.randint([LO]*NUM_INPUTS, [HI]*NUM_INPUTS)
    #samples = list(range(LO, HI+1))
    samples_out = list(map(fibonacci, samples))

    try:

        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        # 1 page worth of code!
        mu.mem_map(BASE_ADDR, PAGE_SIZE)
        # limited stack... Ah! Bummer.
        mu.mem_map(STACK_PAGE, BASE_STACK - STACK_PAGE)

        mu.mem_write(BASE_ADDR, code)

        mu.reg_write(UC_X86_REG_RAX, 0x0)
        mu.reg_write(UC_X86_REG_RCX, NUM_INPUTS)
        mu.reg_write(UC_X86_REG_RBP, BASE_STACK)
        mu.reg_write(UC_X86_REG_RSP, BASE_STACK)

        mu.hook_add(UC_HOOK_INTR, handle_INT)
        mu.emu_start(BASE_ADDR, BASE_ADDR + PAGE_SIZE)
        uc = mu
        debug(f"RIP: {hex(uc.reg_read(UC_X86_REG_RIP))}")
        debug(f"RAX: {hex(uc.reg_read(UC_X86_REG_RAX))}")
        debug(f"RDI: {hex(uc.reg_read(UC_X86_REG_RDI))}")
        debug(f"RBP: {hex(uc.reg_read(UC_X86_REG_RBP))}")
        debug(f"RSP: {hex(uc.reg_read(UC_X86_REG_RSP))}")
        debug(f"Shadow Stack : {list(map(hex, shadow_stack))}")
        exit(42)
    except UcError as e:
        print("ERROR: %s" % e)
        print("rip: 0x%x" % mu.reg_read(UC_X86_REG_RIP))

