# SigElf

SigElf is an open-source project designed to implement an ELF signing system.\
Its primary goal is to provide a straightforward set of tools for signing and verifying ELF binaries.\
The project is released under the LGPL3.

Key Components:

- CLI Tool: A command-line interface for verifying and signing binaries.
- libsigelf: A library for working with signatures.
- ksigelf: A kernel module intended to prevent unauthorized binaries from executing (in conceptual stage).
- sigelf-patches: Patches for the GNU C Library to enable verification of libraries in dynamic environments (in conceptual stage).

Dependencies:

- OpenSSL
- POSIX libc