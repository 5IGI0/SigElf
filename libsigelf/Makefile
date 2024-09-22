TARGET=lib/libsigelf.a
SRCS=$(wildcard src/*.c)
OBJS=${SRCS:.c=.o}
CFLAGS=-Wall -Wextra -std=c99 -I./include/ -g3
CC := gcc

all: .PH0NY ${TARGET}

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

