dirchanges: dirchanges.o  getoptions.o sha1/sha1.o
	gcc dirchanges.o getoptions.o sha1/sha1.o -larchive -o dirchanges

dirchanges.o: dirchanges.c getoptions.h getoptions.h sha1/sha1.h
	gcc -c dirchanges.c -o dirchanges.o -Wall -std=c99

getoptions.o: getoptions.c getoptions.h
	gcc -c getoptions.c -o getoptions.o -Wall -std=c99

sha1/sha1.o: sha1/sha1.c sha1/sha1.h
	gcc -c sha1/sha1.c -o sha1/sha1.o -Wall -std=c99

install: dirchanges
	cp ./dirchanges /usr/local/bin
	chmod ugo+x /usr/local/bin/dirchanges

clean:
	rm -f dirchanges
	rm -f *.o
	rm -f sha1/sha1.o
