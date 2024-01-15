from ..compiler import compiler

from ctypes import cdll,c_ubyte
from os import getpid
from contextlib import redirect_stdout
import io

crunner = cdll.LoadLibrary('./ngc_runner.so')

class NgRunner():
    def __init__(self, ng_source: compiler.NgCode):
        self.ng_source = ng_source
        tmpcode = self.ng_source.get_shellcode()
        self.shellcode = (c_ubyte * len(tmpcode)).from_buffer_copy(tmpcode)
    
    def execute(self, forking:bool=True)->int:
        if (forking):
            print("[*] Injecting in self-fork [+{}]...".format(getpid()))
        else:
            print("[*] Injecting in current execution...")
        
        if not forking:
            res = crunner.ngc_jexec(self.shellcode, 0)
            return res

        pid = crunner.ngc_stage1(1)
        print("[*] Attached to the process with PID {}.".format(pid))
        addr = crunner.ngc_stage2(self.shellcode)
        print("[*] Found section mapped with r-xp permissions.")
        print("[*] Injected payload at address 0x{:02x}.".format(addr&0xffffffff))
        print("[*] Sucessfuly jumped to the code.")
        return crunner.ngc_stage3()