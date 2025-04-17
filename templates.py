"""
Templates.py:

Full of scripts that do the general setup for certain exploits
"""
import subprocess
from typing import Literal
import pwn
import sys


def line2addr(line: str) -> int:
    line = line.split()[0]  # get rid of everything but the address
    line = line[:-1]  # get rid of the colon at the end

    return int(line, 16)


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
    addr = line2addr(out)

    if bits == 32:
        return pwn.p32(addr)
    else:
        return pwn.p64(addr)


def get_addr_from_leak(
        elf: str,
        leak_addr: str,
        leak_name: str = "vuln",
        func_name: str = "win",
        skip_amt: int = 0,
        bits: Literal[32, 64] = 64) -> bytes:
    """
    Finds an address of a function within a PIE enabled binary.

    :param elf: name of the binary
    :param leak_addr: the address of a function leak in the binary
    :param leak_name: the name of the leaked function (defaults to "vuln")
    :param func_name: the name of the function to find (defaults to "win")
    :param skip_amt: the amount of instructions in the function to skip (defaults to 0)
    :param bits: whether the returned address should be a 64-bit or 32-bit address (defaults to 64)

    :return: the little-endian address of the function (or the instruction of the function that was skipped to)
    """
    out = subprocess.run(f"objdump -d {elf}", shell=True, capture_output=True, text=True).stdout.split("\n")
    lines = [None, None]  # lines[0] is for the leak_address line, lines[1] is for func_address
    for i in range(len(out)):
        line = out[i]
        if leak_name in line:
            lines[0] = (i + 1)
        elif func_name in line:
            lines[1] = (i + 1)

        if None not in lines:  # both lines with the function addresses have been found, loop should be exited
            break

    # null checking to ensure that both functions actually exist within the binary
    if lines[0] is None:
        raise ValueError(f"get_addr_from_leak: function {leak_name} not found in binary. Aborting")
    if lines[1] is None:
        raise ValueError(f"get_addr_from_leak: function {func_name} not found in binary. Aborting")

    # get the base from the leak, then get the desired function address from the base
    start = int(leak_addr, 16) - line2addr(out[lines[0]])
    addr = start + line2addr(out[lines[1] + skip_amt])

    # return the address in the desired size
    if bits == 32:
        return pwn.p32(addr)
    else:
        return pwn.p64(addr)


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

    # run through all the children to see if one of them is sh
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
