fileintegrity: fileintegrity.o sha1/sha1.o
	gcc fileintegrity.o sha1/sha1.o -larchive -o fileintegrity

fileintegrity.o: fileintegrity.c
	gcc -c fileintegrity.c -o fileintegrity.o -Wall

sha1/sha1.o: sha1/sha1.c sha1/sha1.h
	gcc -c sha1/sha1.c -o sha1/sha1.o -Wall

clean:
	rm -f fileintegrity
	rm -f *.o
	rm -f sha1/sha1.o
