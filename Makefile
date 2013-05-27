dirchanges: dirchanges.o sha1/sha1.o
	gcc dirchanges.o sha1/sha1.o -larchive -o dirchanges

dirchanges.o: dirchanges.c
	gcc -c dirchanges.c -o dirchanges.o -Wall

sha1/sha1.o: sha1/sha1.c sha1/sha1.h
	gcc -c sha1/sha1.c -o sha1/sha1.o -Wall

clean:
	rm -f dirchanges
	rm -f *.o
	rm -f sha1/sha1.o
