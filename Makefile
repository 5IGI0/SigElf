
all: libsigelf/lib/libsigelf.a cli/bin/sigelf .ph0ny

cli/bin/sigelf:
	make -C cli/

libsigelf/lib/libsigelf.a:
	make -C libsigelf/

fclean: .ph0ny
	make -C cli/ fclean
	make -C libsigelf/ fclean

re: fclean all .ph0ny

.ph0ny: