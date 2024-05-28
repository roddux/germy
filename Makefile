default: debug

CFLAGS=-Wall -Wextra -pedantic -Wundef -Wshadow -Wpointer-arith -std=c17 -Wconversion

debug:
	gcc -Og -g -ggdb $(CFLAGS) -static germy.c -DDEBUG -o germy_debug

release:
	gcc $(CFLAGS) -static germy.c -o germy_release
	strip germy_release

clean:
	rm -f -- germy_debug germy_release

.PHONY: default debug release clean