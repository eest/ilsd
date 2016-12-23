ilsd: ilsd.c
	cc -o ilsd -pedantic -W -Wmissing-prototypes -Wall -Wextra -Wno-unused-parameter -Werror -g -std=c99 ilsd.c -lpcap -lsqlite3

ilsd.c: ilsd.h

clean:
	rm ilsd
