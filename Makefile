dirchanges: dirchanges.o  getoptions.o bufferedfile.o sha256/sha256.o
	gcc dirchanges.o getoptions.o bufferedfile.o sha256/sha256.o -larchive -o dirchanges

dirchanges.o: dirchanges.c getoptions.h getoptions.h sha256/sha256.h
	gcc -c dirchanges.c -o dirchanges.o -Wall -std=c99

getoptions.o: getoptions.c getoptions.h
	gcc -c getoptions.c -o getoptions.o -Wall -std=c99

bufferedfile.o: bufferedfile.c bufferedfile.h
	gcc -c bufferedfile.c -o bufferedfile.o -Wall -std=c99

sha256/sha256.o: sha256/sha256.c sha256/sha256.h
	gcc -c sha256/sha256.c -o sha256/sha256.o -Wall -std=c99

install: dirchanges
	cp ./dirchanges /usr/local/bin
	chmod ugo+x /usr/local/bin/dirchanges

clean:
	rm -f dirchanges
	rm -f *.o
	rm -f sha256/sha256.o
