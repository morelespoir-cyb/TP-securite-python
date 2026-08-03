"""
Precomputed ROR13 hashes for common Windows APIs used by Metasploit-style
shellcodes.

The hash algorithm walks the API name, ROR-13s the accumulator and adds
each byte. Full reference:
    https://en.wikipedia.org/wiki/Position-independent_code#PIC_in_shellcodes
    https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm

We only include the APIs actually referenced by the 3 course shellcodes
(easy/medium/hard) plus a few classics for future-proofing.
"""


def ror13_hash(name: str) -> int:
    """
    Compute the ROR13 hash of an API name, terminated by a null byte
    (Metasploit convention). Returns a 32-bit value.
    """
    h = 0
    for byte in (name + "\x00").encode("ascii"):
        h = (((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF) + byte
        h &= 0xFFFFFFFF
    return h


# Common Windows APIs referenced by the course shellcodes.
_API_NAMES: list[str] = [
    # kernel32
    "LoadLibraryA",
    "GetProcAddress",
    "VirtualAlloc",
    "VirtualProtect",
    "CreateProcessA",
    "WinExec",
    "ExitProcess",
    "ExitThread",
    "WaitForSingleObject",
    "GetVersion",
    # urlmon (used by easy shellcode)
    "URLDownloadToFileA",
    "URLDownloadToFile",
    # ws2_32 (used by hard shellcode — reverse shell)
    "WSAStartup",
    "WSASocketA",
    "connect",
    "recv",
    "send",
    "closesocket",
    "bind",
    "listen",
    "accept",
]


# hash → API name
API_HASHES: dict[int, str] = {ror13_hash(name): name for name in _API_NAMES}