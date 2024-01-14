import sys; sys.path.append('/'.join(sys.path[0].split("/")[:-1]))

import ngc
from os import system

asm = ngc.compiler.NgCode(ngc.Arch.x86_64)

system("gcc payloads/idgr.c -o payloads/idexe")
open("/tmp/me", "wb").write(
    open("payloads/idexe", "rb").read()
)
system("chmod +x /tmp/me")

asm.section("text")
asm.label("_start")


asm.xor("rdx", "rdx")
asm.straddr("rdi", "//tmp/me") ## Basically in 64bit we can declare a 8 bytes string as a 64bit integer, so this payload can bypass this 8 chars limit by copying an execuable
asm.push("rsp")                ## Into /tmp/me, the shortest path that grant write permissions
asm.push("rax")
asm.push("rdi")

asm.mov("al", 0x3B)
asm.syscall()

asm.jmp("$")

asm.section("data")

shellcode = asm.get_shellcode()
runner    = ngc.runner.NgRunner(asm)


print(asm)
print(shellcode)

ret = runner.execute()
print("Shellcode returned: {}".format(ret))