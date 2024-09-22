libsigelf

A library for working with ELF signatures.

== TODO ==

Functions:
[ ] AddTrustedCertificate
[ ] LoadSystemTrustedCertificates (loads certs from /etc/sigelf/certs and/or ~/.config/sigelf/certs)
[ ] IsSignerTrusted
[ ] AddSigningOption

Formats:
[x] ELF64
[ ] ELF32 (need to edit the makefile to compile 2 times sig_elf.c)
[ ] hashbang

Others:
[ ] Doc