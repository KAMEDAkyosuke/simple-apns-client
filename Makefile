gCC         = clang
CFLAGS    += --std=c99 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -pedantic
LDFLAGS   +=
LDLIBS    += -lssl -lcrypto
OBJS       = simple-apns-client.o simple-tcp-server.o socketlist.o
TARGETS    = main

main: main.c $(OBJS)
	$(CC) -o main main.c $(OBJS) $(CFLAGS) $(LDFLAGS) $(LDLIBS) $(ARGS)

simple-apns-client.o: simple-apns-client.c
	$(CC) -c simple-apns-client.c $(CFLAGS) $(ARGS)

simple-apns-client.c: simple-apns-client.h

simple-tcp-server.o: simple-tcp-server.c
	$(CC) -c simple-tcp-server.c $(CFLAGS) $(ARGS)

simple-tcp-server.c: simple-tcp-server.h

socketlist.o: socketlist.c
	$(CC) -c socketlist.c $(CFLAGS) $(ARGS)

socketlist.c: socketlist.h

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS)

.PHONY: check-syntax
check-syntax:
	$(CC) $(CFLAGS) -fsyntax-only $(CHK_SOURCES)
