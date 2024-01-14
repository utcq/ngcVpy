from . import param as npar

from os import popen as _opopen, remove as _oremove, system as _osystem
from math import ceil

class NgCode:
    def __init__(self, arch:npar.Arch):
        self.code_buffer: list[str] = []
        self.tabin = 0
        self.arch = arch
    
    def mov(self, target:any, source:any):
        self.code_buffer.append(
            ("\t"*self.tabin)+"mov {},{}".format(
                str(target).lower(),
                str(source).lower()
            )
        )
    
    def add(self, target:any, source:any):
        self.code_buffer.append(
            ("\t"*self.tabin)+"add {},{}".format(
                str(target).lower(),
                str(source).lower()
            )
        )
    
    def xor(self, target:any, source:any):
        self.code_buffer.append(
            ("\t"*self.tabin)+"xor {},{}".format(
                str(target).lower(),
                str(source).lower()
            )
        )
    
    def shr(self, target:any, source:any):
        self.code_buffer.append(
            ("\t"*self.tabin)+"shr {},{}".format(
                str(target).lower(),
                str(source).lower()
            )
        )
    
    def syscall(self):
        self.code_buffer.append(
            ("\t"*self.tabin)+"syscall"
        )
    
    def int(self, value:int):
        self.code_buffer.append(
            ("\t"*self.tabin)+"int {}".format(str(value))
        )
    
    def ret(self):
        self.code_buffer.append(
            ("\t"*self.tabin)+"ret"
        )
    
    def jmp(self, name:str):
        self.code_buffer.append(
            ("\t"*self.tabin)+"jmp {}".format(name)
        )
    
    def call(self, name:str):
        self.code_buffer.append(
            ("\t"*self.tabin)+"call {}".format(name)
        )
    
    def strdef(self, val:str):
        self.code_buffer.append(
            ("\t"*self.tabin)+"msg db \"{}\"".format(val.replace("\0", "\\0").replace("\n", "\\n"))
        )
    
    def __strbytes__(self, string:str):
        values = list(range(0, ceil(len(string)/4)))
        vindex = 0


        for i in range(0,ceil(len(string)/4)):
            values[i] = ""

        for i in range(0,len(string)):
            if (i!=0 and i%4 < 1): vindex+=1
            values[vindex] += str(string[i])

        for i in range(0,ceil(len(string)/4)):
            val = ''.join(list(reversed(values[i])))
            res = "0x"
            for char in val:
                res+=hex(ord(char))[2:]
            res += "; " + val
            values[i] = res
        values = list(reversed(values))
        return values
    
    def straddr(self, reg:str, val:str):

        if (len(val)<=8):
            self.mov("qword rbx", "'{}'".format(str(val)))
            self.shr("rbx", 0x8)
            self.push("rbx")
            self.mov(reg, "rsp")
        else:
            if self.arch==npar.Arch.i386:
                self.push(0)
                for char in self.__strbytes__(val):
                    self.push(char)
                self.mov(reg, "esp")
            else:
                self.xor("rax", "rax")
                self.push("rax")
                for char in self.__strbytes__(val):
                    self.push(char)
                self.mov(reg, "rsp")
    
    def pop(self, val:str):
        self.code_buffer.append(
            ("\t"*self.tabin)+"pop {}".format(val)
        )
    
    def push(self, val:any):
        self.code_buffer.append(
            ("\t"*self.tabin)+"push {}".format(str(val))
        )

    def label(self, name:str):
        self.code_buffer.append(
            "{}:".format(name)
        )
        self.tabin=1
    
    def section(self, name:str):
        self.code_buffer.append(
            "section .{}".format(name)
        )
        self.tabin=1


    def get_code(self)->list[str]:
        return self.code_buffer

    def get_shellcode(self)->bytearray:
        buffer = ["global _start"] + self.code_buffer
        open("tmp.asm", "w").write('\n'.join(buffer))
        if(_osystem("nasm -f {} tmp.asm -o tmp.o".format(self.arch[0]))): exit(1)
        _oremove("tmp.asm")
        if(_osystem("ld -m {} -s tmp.o -o tmp".format(self.arch[1]))): exit(1)
        _oremove("tmp.o")
        dump = _opopen("objdump -D tmp").read()
        _oremove("tmp")
        shellcode = []
        for line in dump.splitlines():
            if not line.startswith("0000000") and not line.startswith("Disassembly") and not "file format" in line and not line.endswith(">:") and ":" in line:
                hbytes = list(filter(
                    None,
                    line.split(":")[1].split("\t")[1].split(" "),
                ))
                for byte in hbytes:
                    shellcode.append(
                        int(byte, 16)
                    )
        return bytearray(shellcode)
    
    def __repr__(self)->str:
        return ("global _start\n")+'\n'.join(self.code_buffer)