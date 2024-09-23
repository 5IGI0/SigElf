TARGET=bin/sigelf
SRCS=$(wildcard src/*.c)
OBJS=${SRCS:.c=.o}
CFLAGS=-Wall -Wextra -std=c89 -I../libsigelf/include/ -g3
LDFLAGS=-lcrypto
CC := gcc

all: .PH0NY ${TARGET}

%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@

../libsigelf/lib/libsigelf.a:
	make -C ../libsigelf

${TARGET}: ${OBJS} ../libsigelf/lib/libsigelf.a
	mkdir -p $(dir $(TARGET))
	${CC} ${OBJS} -L../libsigelf/lib/ -lsigelf ${LDFLAGS} -o $@

re: .PH0NY fclean all 

clean: .PH0NY
	rm ${OBJS}

fclean: .PH0NY clean
	rm -r bin

.PH0NY:

