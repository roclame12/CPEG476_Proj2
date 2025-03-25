"""
Templates.py:

Full of scripts that does the general setup for certain exploits
"""


import subprocess


def buff_overflow(payload: bytes,
                  fail_str: str | None = None,
                  elf: str = "./a.out",
                  preserve_payload: bool = False) -> bool | None:
    """
    Executes a buffer overflow by making a file and then redirecting it to the program's STDIN

    :param payload: the bytes payload to be sent to the program
    :param fail_str: a string/substring that would be in STDOUT if the buffer overflow fails (optional)
    :param elf: the path to the ELF executable (defaults to ./a.out)
    :param preserve_payload: Whether the payload file should be preserved (defaults to False)

    :return: True if the buffer overflow was successful, False otherwise
    """
    with open("payload_file", "wb") as file:  # input redirection is the easiest way to get raw bytes in input
        file.write(payload)

    print(f"Running executable: {elf}\n\n" + "--------------------------- STDOUT ---------------------------")
    out = subprocess.run(f"{elf} < payload_file", shell=True, capture_output=True, text=True)
    print(f"{out.stdout}\n------------------------- END STDOUT -------------------------\n")

    is_pwn: bool
    if fail_str is None:
        return None
    elif fail_str not in out.stdout:
        print("Exploited!")
        is_pwn = True
    else:
        print("Exploit failed!")
        is_pwn = False

    if not preserve_payload:
        subprocess.run(["rm", "payload_file"])  # clean up temp files

    return is_pwn
