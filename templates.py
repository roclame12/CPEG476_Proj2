"""
Templates.py:

Full of scripts that do the general setup for certain exploits
"""
import subprocess
from typing import Literal
import pwn
import sys


def get_func_addr(elf: str,
                  func_name: str = "win",
                  skip_amt: int = 0,
                  bits: Literal[32, 64] = 64) -> bytes:
    """
    Finds the address of a function within the binary.

    :param elf: name of the binary
    :param func_name: the name of the function to find (defaults to "win")
    :param skip_amt: the amount of instructions in the function to skip (defaults to 0)
    :param bits: whether the returned address should be a 64-bit or 32-bit address (defaults to 64)

    :return: the little-endian address of the function (or the instruction of the function that was skipped to)
    """

    # disassemble and then get <skip_amt> instructions
    out = subprocess.run(f"objdump -d {elf} | grep -A {skip_amt + 1} \"<{func_name}>:\"",
                         shell=True, capture_output=True, text=True).stdout

    out = out.split("\n")[skip_amt + 1]  # get rid of everything but the wanted instruction
    out = out.split()[0]  # get rid of everything but the address
    out = out[:-1]  # get rid of the colon at the end

    addr: bytes
    if bits == 32:
        addr = pwn.p32(int(out, 16))
    else:
        addr = pwn.p64(int(out, 16))

    return addr


def did_shell_spawn(pid: str) -> bool:
    # check if the process itself became a shell
    if "sh" in subprocess.run(["ps", pid], capture_output=True, text=True).stdout:
        return True

    # Check to see if there's a child process spawned that's a shell
    # when a shell doesn't spawn, there's a race condition where Python might not get execution back before
    # the process closes, so the proc entry will be gone before this function starts up, thus the try...except block
    try:
        with open(f"/proc/{pid}/task/{pid}/children", "r") as file:
            children = file.read().split()
    except FileNotFoundError:
        print("is_shell_spawned: process closed before function could launch, shell probably didn't spawn", file=sys.stderr)
        return False

    spawned = False
    for child in children:
        ps_out = subprocess.run(["ps", child], capture_output=True, text=True).stdout
        if "sh" in ps_out:  # hopefully all of these CTF binaries use sh
            spawned = True
            break

    return spawned


def buff_overflow(payload: bytes,
                  proc: pwn.process,
                  interactive: bool = True,
                  preserve_payload: bool = False) -> bool | None:
    """
    Executes a buffer overflow by making a file and then redirecting it to the program's STDIN

    :param payload: the bytes payload to be sent to the program
    :param proc: The process to exploit
    :param interactive: whether to give control to the user once the exploit is complete (defaults to True)
    :param preserve_payload: Whether the payload file should be preserved (defaults to False)

    :return: True if the buffer overflow was successful, False otherwise
    """
    if preserve_payload:  # provide payload as a file so it can be used in manual debuggers easily (that aren't GDB, since pwntools can do that pretty easy)
        with open("payload_file", "wb") as file:
            file.write(payload)

    proc.sendline(payload)
    if interactive:
        proc.interactive()

    # attempt to encode stdout into ascii, (exploit weirdness might make this not work)
    try:
        stdout = str(proc.recv(timeout=1), encoding="ascii")
    except subprocess.CalledProcessError:
        stdout = proc.recv(timeout=1)

    print(
        "\n\n--------------------------- STDOUT ---------------------------\n"
        f"{stdout}"
        "\n------------------------- END STDOUT -------------------------\n"
        )

    is_pwned = did_shell_spawn(str(proc.pid))
    proc.close()

    if is_pwned:
        print("Exploit was successful")
    else:
        print("Exploit was NOT successful")

    return is_pwned
