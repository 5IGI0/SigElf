TARGET=lib/libsigelf.a
SRCS=$(wildcard src/*.c)
ELF_SRCS=$(wildcard src/elf/*.c)
OBJS=${SRCS:.c=.o} ${ELF_SRCS:.c=.32.o} ${ELF_SRCS:.c=.64.o}
CFLAGS=-Wall -Wextra -std=c99 -I./include/ -g3
CC := gcc

all: .PH0NY ${TARGET}

%.64.o: %.c
	${CC} -DELF64=1 ${CFLAGS} -c $< -o $@

%.32.o: %.c
	${CC} -DELF32=1 ${CFLAGS} -c $< -o $@

%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@

${TARGET}: ${OBJS}
	mkdir -p $(dir $(TARGET))
	ar -rcs ${TARGET} ${OBJS}

re: .PH0NY fclean all 

clean: .PH0NY
	rm -f ${OBJS}

fclean: .PH0NY clean
	rm -rf lib

.PH0NY:

