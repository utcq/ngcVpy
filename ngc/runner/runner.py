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

        res = 0
        f = io.StringIO()
        with redirect_stdout(f):
             res = crunner.NGC_ShellRunner(self.shellcode, (1 if forking else 0 ))
        s = f.getvalue()
        print("REP: {}".format(repr(s)))
        return res