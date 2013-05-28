/* DIRCHANGES Copyright (c) 2013 Adrian Lopez

   This software is provided 'as-is', without any express or implied warranty.
   In no event will the authors be held liable for any damages arising from the
   use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you must not
      claim that you wrote the original software. If you use this software in a
      product, an acknowledgment in the product documentation would be 
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original software.

   3. This notice may not be removed or altered from any source distribution.
*/
#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <malloc.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include "sha1/sha1.h"

#define FILENAME_MAX_SIZE 256
#define ARCHIVE_BUFFER_SIZE 256

#define ISFLAG(a,b) ((a & b) == b)
#define SETFLAG(a,b) (a |= b)
#define MAX(X, Y) (X > Y ? X : Y)
#define MIN(X, Y) (X < Y ? X : Y)

#define F_PRINTHASHES 0x0001
#define F_VERBOSE 0x0002

unsigned long flags = 0;

struct string
{
	char *chars;
	size_t allocated;
};

struct directoryentry
{
	struct string name;
	struct string fullpath;
	unsigned char type;
	uint8_t sha1[SHA1_DIGEST_SIZE];
};

struct directoryentrycollection
{
	size_t length;
	size_t allocated;
	struct directoryentry *entries;
};

struct BUFFEREDFILE
{
	FILE *stream;
	size_t maxlookahead;
	uint64_t rollback;
	uint64_t fpos;
	int eof;

	void *buffer;
	uint64_t buffer0start;
	uint64_t buffer0end;
	uint64_t buffer1start;
	uint64_t buffer1end;
};

struct libarchivedata
{
	FILE *stream;
	struct string name;
	struct BUFFEREDFILE *bstream;
	unsigned char buffer[ARCHIVE_BUFFER_SIZE];	
};

struct BUFFEREDFILE *bufferedfile_init(FILE *stream, size_t maxlookahead)
{
	struct BUFFEREDFILE *f = malloc(sizeof(struct BUFFEREDFILE));
	if (!f) 
		exit(1);

	f->buffer = malloc(maxlookahead * 2);
	if (!f->buffer)
	{
		free(f);
		exit(1);
	}

	f->buffer0start = 0;
	f->buffer0end = 0;
	f->buffer1start = 0;
	f->buffer1end = 0;

	f->stream = stream;
	f->maxlookahead = maxlookahead;
	f->fpos = 0;
	f->rollback = 0;
	f->eof = 0;

	return f;
}

void bufferedfile_destroy(struct BUFFEREDFILE *f)
{
	free(f->buffer);
	free(f);
}

int Intersection(uint64_t *i0, uint64_t *i1, uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1)
{
	if (a1 <= b0 || b1 <= a0)
		return 0;

	*i0 = MAX(a0, b0);
	*i1 = MIN(a1, b1);

	return 1;
}

size_t bufferedfile_getbytes(void *buf, size_t count, struct BUFFEREDFILE *file)
{
	size_t bytesread;
	uint64_t i0;
	uint64_t i1;

	if (count > file->maxlookahead)
		return 0;

	/* Read past end of buffered data? */
	if (!file->eof && file->fpos + count > MAX(file->buffer0end, file->buffer1end))
	{
		/* Does buffer 0 have stale contents? */
		if (file->buffer0end <= file->buffer1end)
		{
			/* Replace buffer 0's contents with fresh data. */
			file->buffer0start = file->buffer1end;

			size_t read = fread(file->buffer, 1, file->maxlookahead, file->stream);
			if (read != count)
				file->eof = 1;

			file->buffer0end = file->buffer0start + read;
		}
		else
		{
			/* Replace buffer 1's contents with fresh data. */
			file->buffer1start = file->buffer0end;

			size_t read = fread(file->buffer + file->maxlookahead, 1, file->maxlookahead, file->stream);
			if (read != count)
				file->eof = 1;

			file->buffer1end = file->buffer1start + read;
		}
	}

	bytesread = 0;

	/* Does read operation include data from buffer 0? */
	if (Intersection(&i0, &i1, file->fpos, file->fpos + count, file->buffer0start, file->buffer0end))
	{
		/* Copy contents from buffer 0 onto target buf. */
		bytesread = (size_t)(i1 - i0);

		if (file->buffer0start <= i0)
			memcpy(buf, file->buffer + (size_t)(i0 - file->buffer0start), bytesread); 
		else
			memcpy(buf + (size_t)(file->buffer0start - i0), file->buffer, bytesread); 

		file->fpos += bytesread;
	}

	/* Does read operation include data from buffer 1? */
	if (Intersection(&i0, &i1, file->fpos, file->fpos + count, file->buffer1start, file->buffer1end))
	{
		/* Copy contents from buffer 1 onto target buf. */
		bytesread = (size_t)(i1 - i0);

		if (file->buffer1start <= i0)
			memcpy(buf, file->buffer + file->maxlookahead + (size_t)(i0 - file->buffer1start), bytesread);
		else
			memcpy(buf + (size_t)(file->buffer1start - i0), file->buffer + file->maxlookahead, bytesread);

		file->fpos += bytesread;
	}

	return bytesread;
}

void bufferedfile_ungetbytes(struct BUFFEREDFILE *file)
{
	file->fpos = file->rollback;
}

struct string string_fromchars(const char *chars)
{
	struct string s;
	s.allocated = strlen(chars) + 1;
	s.chars = malloc(s.allocated);

	if (s.chars == 0)
		exit(1);

	strcpy(s.chars, chars);

	return s;
}

int string_split(struct string *s, struct string **parts)
{
	return 0;
}

void string_append(struct string *s, char *chars)
{
	size_t needed = strlen(s->chars) + strlen(chars) + 1;

	if (needed > s->allocated)
	{
		s->allocated = needed * 2;
		
		char *newchars = realloc(s->chars, s->allocated);
		
		if (newchars == 0)
			exit(1);

		s->chars = newchars;
	}

	strcat(s->chars, chars);
}

void string_removetrailingcharacter(struct string *s, char c)
{
	size_t spos = strlen(s->chars) - 1;

	while (spos >= 0 && s->chars[spos] == c)
		--spos;
		
	s->chars[spos + 1] = '\0';
}

int string_parse_rawhex(struct string *s, uint8_t *buf)
{
	return 0;
}

struct string string_fetchtoken(struct string *s, size_t *offset, char *delim)
{
	struct string token = string_fromchars("");
	
	size_t length = strlen(s->chars);
	while (*offset < length && strchr(delim, s->chars[*offset]) != 0)
		++*offset;

	for (; *offset < length; ++*offset)
	{
		if (strchr(delim, s->chars[*offset]) != 0)
		{
			while (*offset < length && strchr(delim, s->chars[*offset]) != 0)
				++*offset;
			break;
		}
		
		char c[2];
		c[0] = s->chars[*offset];
		c[1] = '\0';

		string_append(&token, c);
	}

	return token;
}

void string_free(struct string s)
{
	free(s.chars);
}

void string_freemany(struct string *s, int count)
{
	int x;

	for (x = 0; x < count; ++x)
		string_free(s[x]);
}

char *relativepath(const char *path, const char *root)
{
	char *newpath = strstr(path, root);

	if (newpath != path)
		return NULL;

	newpath = newpath + strlen(root);
	
	if (*newpath == '/')
		return newpath + 1;
	else
		return 0;
}

void directoryentry_destroy(struct directoryentry *directory)
{
	string_free(directory->name);
}

struct directoryentrycollection *directoryentrycollection_new()
{
	struct directoryentrycollection *collection = malloc(sizeof(struct directoryentrycollection));
	if (collection == 0)
		exit(1);

	collection->entries = malloc(sizeof(struct directoryentry));
	if (collection->entries == 0)
	{
		free(collection);
		exit(1);
	}

	collection->allocated = 1;
	collection->length = 0;

	return collection;
}

struct directoryentry *directoryentrycollection_add(struct directoryentrycollection *to, struct directoryentry *what)
{
	if (to->length == to->allocated)
	{
		struct directoryentry *newdata = realloc(to->entries, sizeof(struct directoryentry) * to->allocated * 2);
		if (newdata == 0)
			exit(1);

		to->allocated *= 2;
		to->entries = newdata;
	} 

	to->entries[to->length] = *what;
	
	return &to->entries[to->length++];
}

void directoryentrycollection_free(struct directoryentrycollection *collection)
{	
	if (collection == 0)
		return;

	size_t e;
	for (e = 0; e < collection->length; ++e)
		directoryentry_destroy(&collection->entries[e]);

	free(collection->entries);
	free(collection);
}

int getfiledigest(char *path, uint8_t *digest)
{
	SHA1_CTX sha1ctx;

	FILE *stream = fopen(path, "rb");
	if (!stream)
		return 0;

	SHA1_Init(&sha1ctx);

	struct BUFFEREDFILE *bf = bufferedfile_init(stream, ARCHIVE_BUFFER_SIZE);
	if (!bf)
	{
		fclose(stream);
		return 0;
	}
	
	uint8_t buf[ARCHIVE_BUFFER_SIZE];

	size_t read = bufferedfile_getbytes(buf, ARCHIVE_BUFFER_SIZE, bf);
	while (read > 0)
	{
		SHA1_Update(&sha1ctx, buf, read);
		read = bufferedfile_getbytes(buf, ARCHIVE_BUFFER_SIZE, bf);
	}

	SHA1_Final(&sha1ctx, digest);

	fclose(stream);

	bufferedfile_destroy(bf);

	return 1;
}

char *mgetcwd()
{
	char *buf;
	size_t bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf)
		exit(1);

	while (getcwd(buf, bufsize) == 0)
	{
		if (errno == ERANGE)
		{
			bufsize *= 2;
			
			char *newbuf = realloc(buf, bufsize);
			if (!newbuf)
			{
				free(buf);
				exit(1);
			}
			
			buf = newbuf;
		}
		else
		{
			free(buf);
			return 0;
		}
	}

	return buf;
}

int openarchive(struct archive *a, void *data)
{
	struct libarchivedata *ldata = data;

	if (strcmp(ldata->name.chars, "-") != 0)
	{
		ldata->stream = fopen(ldata->name.chars, "rb");
		if (!ldata->stream)
			return ARCHIVE_FATAL;
	}
	else
	{
		freopen(NULL, "rb", stdin);
		ldata->stream = stdin;
	}

	ldata->bstream = bufferedfile_init(ldata->stream, ARCHIVE_BUFFER_SIZE);

	if (!ldata->bstream)
		return ARCHIVE_FATAL;

	return ARCHIVE_OK;
}

ssize_t readarchive(struct archive *a, void *data, const void **buffer)
{
	struct libarchivedata *ldata = data;

	size_t read = bufferedfile_getbytes(ldata->buffer, ARCHIVE_BUFFER_SIZE, ldata->bstream);
	*buffer = ldata->buffer;

	return read;
}

int closearchive(struct archive *a, void *data)
{
	struct libarchivedata *ldata = data;

	if (strcmp(ldata->name.chars, "-") != 0)
		fclose(ldata->stream);

	bufferedfile_destroy(ldata->bstream);

	return ARCHIVE_OK;
}

void directoryentry_print(struct directoryentry *de)
{
	switch (de->type)
	{
		case DT_DIR:
			printf("D ");
			break;
		case DT_REG:
			printf("R ");
			break;
		default:
			printf("? ");
			break;
	}

	int x;

	if (de->type == DT_REG)
	{
		for (x = 0; x < SHA1_DIGEST_SIZE; ++x)
			printf("%02x", de->sha1[x]);		

		printf(" ");
	}

	printf("%s\n", de->fullpath.chars);
}

int directoryentry_equalbydigest(const struct directoryentry *de1, const struct directoryentry *de2)
{
	int x;
	for (x = 0; x < SHA1_DIGEST_SIZE; ++x)
		if (de1->sha1[x] != de2->sha1[x])
			return 0;

	return 1;
}

int directoryentry_comparebyfilename(const void *de1, const void *de2)
{
	const struct directoryentry *c1 = de1;
	const struct directoryentry *c2 = de2;

	return strcmp(c1->name.chars, c2->name.chars);
}

int directoryentry_getfromstring(struct string *s, struct directoryentry *entry)
{
	size_t offset = 0;

	struct string type = string_fetchtoken(s, &offset, " ");
	if (type.chars[0] != '\0')
	{
		if (strcmp(type.chars, "R") == 0) /* Regular file. */
		{	
			entry->type = DT_REG;

			string_free(type);

			struct string signature = string_fetchtoken(s, &offset, " ");
			if (signature.chars[0] != '\0')
			{
				if (!string_parse_rawhex(&signature, entry->sha1))
				{
					string_free(signature);
					return 0;
				}
				else
				{
					entry->fullpath = string_fetchtoken(s, &offset, "");

					string_free(signature);
					return 1;
				}
			}
			else
			{
				string_free(signature);
				return 0;
			}
		}
		else if (strcmp(type.chars, "D") == 0) /* Directory. */
		{
			entry->type = DT_DIR;			
			entry->fullpath = string_fetchtoken(s, &offset, "");

			string_free(type);

			return 1;
		}
		else /* Unknown type. */
		{
			string_free(type);
			return 0;
		}
	}

	string_free(type);

	return 0;
}

void directoryentrycollection_sort(struct directoryentrycollection *collection)
{
	qsort(collection->entries, collection->length, sizeof(struct directoryentry), directoryentry_comparebyfilename);
}

void directoryentrycollection_compare(struct directoryentrycollection *c1, struct directoryentrycollection *c2, char *pathfrom, char *pathto)
{
	int differencesfound = 0;

	directoryentrycollection_sort(c1);
	directoryentrycollection_sort(c2);

	size_t c1pos = 0;
	size_t c2pos = 0;

	while (c1pos < c1->length && c2pos < c2->length)
	{
		int cmp = strcmp(c1->entries[c1pos].name.chars, c2->entries[c2pos].name.chars);

		if (cmp == 0)
		{
			if (c1->entries[c1pos].type == DT_REG && c2->entries[c2pos].type == DT_REG)
			{
				if (!directoryentry_equalbydigest(&c1->entries[c1pos], &c2->entries[c2pos]))
				{
					differencesfound = 1;				
					printf("Different in %s: %s\n", pathto, c2->entries[c2pos].fullpath.chars);
				}
			}
			else if (c1->entries[c1pos].type != c2->entries[c2pos].type)
			{
				differencesfound = 1;
				printf("Different in %s: %s\n", pathto, c2->entries[c2pos].fullpath.chars);
			}

			c1pos++;
			c2pos++;
		}
		else if (cmp < 0)
		{
			differencesfound = 1;
			printf("Only in %s: %s\n", pathfrom, c1->entries[c1pos].fullpath.chars);
			c1pos++;
		}
		else
		{
			differencesfound = 1;
			printf("Only in %s: %s\n", pathto, c2->entries[c2pos].fullpath.chars);
			c2pos++;
		}
	}

	if (c1pos < c1->length || c2pos < c2->length)
	{
		differencesfound = 1;

		while (c1pos < c1->length)
			printf("Only in %s: %s\n", pathfrom, c1->entries[c1pos++].fullpath.chars);
	
		while (c2pos < c2->length)
			printf("Only in %s: %s\n", pathto, c2->entries[c2pos++].fullpath.chars);
	}

	if (!differencesfound)
		printf("No differences found.\n");
}

void directoryentrycollection_printhashes(struct directoryentrycollection *collection, char *root)
{
	printf("DIRHASH1\n");

	size_t e;
	for (e = 0; e < collection->length; ++e)
		directoryentry_print(collection->entries + e);
}

void directoryentry_addfromfilesystem(struct directoryentrycollection *collection, char *path, char *root)
{
	DIR *cd;

	if (path != 0)
		cd = opendir(path);
	else
		cd = opendir(".");

	if (cd == 0)
		exit(1);

	struct dirent *dirinfo;
	while ((dirinfo = readdir(cd)) != 0)
	{
		if (strcmp(dirinfo->d_name, ".") == 0 || strcmp(dirinfo->d_name, "..") == 0)
			continue;

		if (dirinfo->d_type != DT_DIR && dirinfo->d_type != DT_REG)
			continue;

		struct string s = string_fromchars("");
	
		if (path != 0 && strcmp(path, ".") != 0)
		{
			string_append(&s, path);
			string_append(&s, "/");
		}

		string_append(&s, dirinfo->d_name);

		char *rpath = s.chars;
		if (root != 0)
			rpath = relativepath(s.chars, root);

		if (dirinfo->d_type == DT_DIR)
		{
			if (rpath != 0)
			{
				struct directoryentry entry;
				entry.name = string_fromchars(rpath);
				entry.fullpath = string_fromchars(s.chars);
				entry.type = dirinfo->d_type;

				directoryentrycollection_add(collection, &entry);

				if (ISFLAG(flags, F_VERBOSE))		
					fprintf(stderr, "%s\n", s.chars);	
			}

			directoryentry_addfromfilesystem(collection, s.chars, root);
		}
		else if (rpath != 0)
		{
			struct directoryentry entry;
			entry.name = string_fromchars(rpath);	
			entry.fullpath = string_fromchars(s.chars);
			entry.type = dirinfo->d_type;

			if (getfiledigest(s.chars, entry.sha1))
			{
				directoryentrycollection_add(collection, &entry);

				if (ISFLAG(flags, F_VERBOSE))
					fprintf(stderr, "%s\n", s.chars);	
			}
			else
			{
				fprintf(stderr, "error obtaining hash for %s\n", s.chars);
			}
		}

		string_free(s);
	}
	closedir(cd);
}

struct directoryentrycollection *directoryentrycollection_getfromfilesystem(char *path, char *root)
{
	struct directoryentrycollection *collection = directoryentrycollection_new();
	if (!collection)
		exit(1);

	char *cwd = mgetcwd();
	if (cwd == 0)
		exit(1);

	if (chdir(path) != 0)
		exit(1);

	directoryentry_addfromfilesystem(collection, 0, root);

	if (chdir(cwd) != 0)
		exit (1);

	return collection;
}

struct directoryentrycollection *directoryentrycollection_getfromarchive(char *path, char *root)
{
	struct directoryentrycollection *collection = directoryentrycollection_new();
	if (!collection)
		exit(1);

	struct archive *a;
	struct archive_entry *entry;
	
	a = archive_read_new();
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);

	struct libarchivedata ldata;
	ldata.name = string_fromchars(path);

	archive_read_open(a, &ldata, openarchive, readarchive, closearchive);
	while (archive_read_next_header(a, &entry) == ARCHIVE_OK)
	{
		mode_t filetype = archive_entry_filetype(entry);

		if (filetype == AE_IFREG)
		{
			struct string s = string_fromchars(archive_entry_pathname(entry));

			char *rpath = s.chars;
			if (root != 0)
				rpath = relativepath(s.chars, root);

			if (rpath != 0)
			{
				SHA1_CTX sha1ctx;		
				SHA1_Init(&sha1ctx);

				uint8_t buf[8192];
				ssize_t read = archive_read_data(a, buf, 8192);
				while (read > 0)
				{
					SHA1_Update(&sha1ctx, buf, read);

					read = archive_read_data(a, buf, 8192);
				}

				struct directoryentry direntry;
				direntry.name = string_fromchars(rpath);
				direntry.fullpath = string_fromchars(s.chars);
				direntry.type = DT_REG;

				SHA1_Final(&sha1ctx, direntry.sha1);
		
				directoryentrycollection_add(collection, &direntry);
		
				if (ISFLAG(flags, F_VERBOSE))
					fprintf(stderr, "%s\n", s.chars);	
			}
			else
			{
				archive_read_data_skip(a);
			}

			string_free(s);
		}
		else if (filetype == AE_IFDIR)
		{
			struct string s = string_fromchars(archive_entry_pathname(entry));
			string_removetrailingcharacter(&s, '/');

			char *rpath = s.chars;
			if (root != 0)
				rpath = relativepath(s.chars, root);

			if (rpath != 0)
			{
				struct directoryentry direntry;
				direntry.name = string_fromchars(rpath);
				direntry.fullpath = string_fromchars(s.chars);
				direntry.type = DT_DIR;

				directoryentrycollection_add(collection, &direntry);
		
				if (ISFLAG(flags, F_VERBOSE))
					fprintf(stderr, "%s\n", s.chars);	
			}
			else
			{
				archive_read_data_skip(a);
			}

			string_free(s);
		}
		else
		{
			struct string s = string_fromchars(archive_entry_pathname(entry));
			string_removetrailingcharacter(&s, '/');

			archive_read_data_skip(a);

			string_free(s);
		}
	}

	archive_read_close(a);
	archive_read_free(a);

	string_free(ldata.name);

	return collection;
}

struct directoryentrycollection *directoryentrycollection_getfromhashfile(struct BUFFEREDFILE *bfile, char *root)
{
	struct directoryentry entry;

	uint8_t buf[10];
	if (bufferedfile_getbytes(buf, 9, bfile) == 9)
	{
		buf[9] = '\0';
		if (strcmp((char*)buf, "DIRHASH1\n") != 0)
		{
			bufferedfile_ungetbytes(bfile);
			return 0;		
		}
		else
		{
			struct directoryentrycollection *collection = directoryentrycollection_new();
			if (!collection)
				exit(1);

			struct string line = string_fromchars("");

			char c[2];
			c[1] = 0;

			while (bufferedfile_getbytes(c, 1, bfile) == 1)
			{
				switch (c[0])
				{
					case '\n':
						if (directoryentry_getfromstring(&line, &entry))
							directoryentrycollection_add(collection, &entry);
						else
							exit(1);

						line.chars[0] = '\0';
						break;

					default:
						string_append(&line, c);
						break;
				}
			}

			string_free(line);

			return collection;
		}
	}

	bufferedfile_ungetbytes(bfile);
	return 0;
}

int main(int argc, char **argv)
{	
	static struct option long_options[] = 
	{
		{ "froot", 1, 0, 'f' },
		{ "troot", 1, 0, 't' },
		{ "verbose", 0, 0, 'v' },
		{ "hash", 0, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	extern char *optarg;
	extern int optind;
	
	int opt;
	int errors = 0;

	char *froot = 0;
	char *troot = 0;

	while ((opt = getopt_long(argc, argv, "f:t:h", long_options, 0)) != -1)
	{
		switch (opt)
		{
		case 'f':
			froot = optarg;
			break;

		case 't':
			troot = optarg;
			break;

		case 'h':
			SETFLAG(flags, F_PRINTHASHES);
			break;

		case 'v':
			SETFLAG(flags, F_VERBOSE);
			break;

		case '?':
			errors = 1;
			break;
		}
	}

	int nonoptc = argc - optind;
	if (nonoptc < 1)
	{
		fprintf(stderr, "%s: must specify FROM and TO arguments.\n", argv[0]);
		errors = 1;
	}
	else if (nonoptc < 2 && !ISFLAG(flags, F_PRINTHASHES))
	{
		fprintf(stderr, "%s: must specify TO argument.\n", argv[0]);
		errors = 1;
	}
	else if ((nonoptc > 1 && ISFLAG(flags, F_PRINTHASHES)) || nonoptc > 2)
	{
		fprintf(stderr, "%s: too many arguments supplied.\n", argv[0]);
		errors = 1;
	}

	if (errors)
	{
		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		return 0;
	}

	struct directoryentrycollection *collection1 = 0;
	struct directoryentrycollection *collection2 = 0;

	struct stat f1stat;
	struct stat f2stat;

	if (strcmp(argv[optind], "-") != 0 && lstat(argv[optind], &f1stat) != 0)
	{
		fprintf(stderr, "%s: cannot access %s.\n", argv[0], argv[optind]);
		return 0;
	}

	if (!ISFLAG(flags, F_PRINTHASHES))
	{
	 	if (strcmp(argv[optind+1], "-") != 0 && lstat(argv[optind+1], &f2stat) != 0)
		{
			fprintf(stderr, "%s: cannot access %s.\n", argv[0], argv[optind+1]); 
			return 0;
		}

		if (strcmp(argv[optind], "-") == 0 && strcmp(argv[optind+1], "-") == 0)
		{
			fprintf(stderr, "%s: can't read twice from stdin.\n", argv[0]);
			return 0;
		}
	}

	if (strcmp(argv[optind], "-") == 0 || S_ISREG(f1stat.st_mode))
	{
		if (ISFLAG(flags, F_VERBOSE))
			fprintf(stderr, "Reading from archive \"%s\"...\n", argv[optind]);

		collection1 = directoryentrycollection_getfromarchive(argv[optind], froot);
	}
	else if (S_ISDIR(f1stat.st_mode))
	{
		if (ISFLAG(flags, F_VERBOSE))
			fprintf(stderr, "Reading from directory \"%s\"...\n", argv[optind]);
	
		collection1 = directoryentrycollection_getfromfilesystem(argv[optind], froot);
	}

	if (!ISFLAG(flags, F_PRINTHASHES))
	{
		if (strcmp(argv[optind+1], "-") == 0 || S_ISREG(f2stat.st_mode))
		{
			if (ISFLAG(flags, F_VERBOSE))
				fprintf(stderr, "\nReading from archive \"%s\"...\n", argv[optind+1]);

			collection2 = directoryentrycollection_getfromarchive(argv[optind+1], troot);
		}
		else if (S_ISDIR(f2stat.st_mode))
		{	
			if (ISFLAG(flags, F_VERBOSE))
				fprintf(stderr, "\nReading from directory \"%s\"...\n", argv[optind+1]);

			collection2 = directoryentrycollection_getfromfilesystem(argv[optind+1], troot);
		}
	}

	if (ISFLAG(flags, F_VERBOSE))
		fprintf(stderr, "\n");

	if (ISFLAG(flags, F_PRINTHASHES))
		directoryentrycollection_printhashes(collection1, argv[optind]);
	else
		directoryentrycollection_compare(collection1, collection2, argv[optind], argv[optind+1]);

	if (collection2)
		directoryentrycollection_free(collection2);
	
	directoryentrycollection_free(collection1);

	return 0;
}

