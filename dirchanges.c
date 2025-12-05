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

#define PROGRAM_NAME "dirchanges"
#define DIRCHANGES_VERSION "1.0.0"

#define _DEFAULT_SOURCE

#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdarg.h>
#include <malloc.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>

#include "sha256/sha256.h"
#include "getoptions.h"

#define ARCHIVE_BUFFER_SIZE 8192

#define ISFLAG(a,b) ((a & b) == b)
#define SETFLAG(a,b) (a |= b)
#define MAX(X, Y) (X > Y ? X : Y)
#define MIN(X, Y) (X < Y ? X : Y)

#define F_PRINTHASHES  0x0001
#define F_VERBOSE      0x0002
#define F_SHORTSUMMARY 0x0004

char *program_name;

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
	unsigned char hash[SHA256_BYTES_SIZE];
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
	int error;

	void *buffer;
	uint64_t buffer0start;
	uint64_t buffer0end;
	uint64_t buffer1start;
	uint64_t buffer1end;
};

struct libarchivedata
{
	struct BUFFEREDFILE *bstream;
	unsigned char buffer[ARCHIVE_BUFFER_SIZE];
};

void fatalerror(char *message, ...)
{

	va_list ap;

	va_start(ap, message);

	fprintf(stderr, "%s: ", program_name);

	vfprintf(stderr, message, ap);

	fprintf(stderr, "\n");

	exit(1);
}

void warn(char *message, ...)
{
	va_list ap;

	va_start(ap, message);

	fprintf(stderr, "%s: ", program_name);

	vfprintf(stderr, message, ap);

	fprintf(stderr, "\n");
}

struct BUFFEREDFILE *bufferedfile_init(FILE *stream, size_t maxlookahead)
{
	struct BUFFEREDFILE *f = malloc(sizeof(struct BUFFEREDFILE));
	if (!f)
		fatalerror("out of memory!");

	f->buffer = malloc(maxlookahead * 2);
	if (!f->buffer)
	{
		free(f);
		fatalerror("out of memory!");
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
	f->error = 0;

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

size_t _bufferedfile_getbytes(void *buf, size_t count, struct BUFFEREDFILE *file, int buffered)
{
	size_t bytesread;
	uint64_t i0;
	uint64_t i1;

	/* Allow rollback to previous position. */
	file->rollback = file->fpos;

	/* Refresh buffer if necessary. */
	if (buffered)
	{
		/* Reading more than maxlookahead bytes is not permitted on buffered reads. */
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
				{
					file->eof = feof(file->stream);
					file->error = ferror(file->stream);
				}

				file->buffer0end = file->buffer0start + read;
			}
			else
			{
				/* Replace buffer 1's contents with fresh data. */
				file->buffer1start = file->buffer0end;

				size_t read = fread(file->buffer + file->maxlookahead, 1, file->maxlookahead, file->stream);
				if (read != count)
				{
					file->eof = feof(file->stream);
					file->error = ferror(file->stream);
				}

				file->buffer1end = file->buffer1start + read;
			}
		}
	}

	bytesread = 0;

	/* Does read operation include data from buffer 0? */
	if (Intersection(&i0, &i1, file->fpos, file->fpos + count, file->buffer0start, file->buffer0end))
	{
		/* Copy contents from buffer 0 onto target buf. */
		if (file->buffer0start <= i0)
			memcpy(buf, file->buffer + (size_t)(i0 - file->buffer0start), (size_t)(i1 - i0));
		else
			memcpy(buf + (size_t)(file->buffer0start - i0), file->buffer, (size_t)(i1 - i0));

		bytesread += (size_t)(i1 - i0);
	}

	/* Does read operation include data from buffer 1? */
	if (Intersection(&i0, &i1, file->fpos, file->fpos + count, file->buffer1start, file->buffer1end))
	{
		/* Copy contents from buffer 1 onto target buf. */
		if (file->buffer1start <= i0)
			memcpy(buf, file->buffer + file->maxlookahead + (size_t)(i0 - file->buffer1start), (size_t)(i1 - i0));
		else
			memcpy(buf + (size_t)(file->buffer1start - i0), file->buffer + file->maxlookahead, (size_t)(i1 - i0));

		bytesread += (size_t)(i1 - i0);
	}

	/* Is there any data left to read? */
	if (!file->eof && bytesread < count)
	{
		/* Read unbuffered data directly from stream. */
		size_t read = fread(buf + bytesread, 1, count - bytesread, file->stream);
		if (read != count - bytesread)
			file->eof = 1;

		bytesread += read;

		/* Can't roll back unbuffered reads. */
		file->rollback = file->fpos + bytesread;
	}

	file->fpos += bytesread;

	return bytesread;
}

size_t bufferedfile_getbytes(void *buf, size_t count, struct BUFFEREDFILE *file)
{
	return _bufferedfile_getbytes(buf, count, file, 1);
}

size_t bufferedfile_getbytes_unbuffered(void *buf, size_t count, struct BUFFEREDFILE *file)
{
	return _bufferedfile_getbytes(buf, count, file, 0);
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
		fatalerror("out of memory!");

	strcpy(s.chars, chars);

	return s;
}

void string_append(struct string *s, const char *chars)
{
	size_t needed = strlen(s->chars) + strlen(chars) + 1;

	if (needed > s->allocated)
	{
		s->allocated = needed * 2;

		char *newchars = realloc(s->chars, s->allocated);

		if (newchars == 0)
			fatalerror("out of memory!");

		s->chars = newchars;
	}

	strcat(s->chars, chars);
}

void string_removetrailingcharacter(struct string *s, char c)
{
	const size_t len = strlen(s->chars);
	if (len == 0)
		return;

	size_t spos = len - 1;

	while (spos > 0 && s->chars[spos] == c) {
		s->chars[spos] = '\0';
		--spos;
	}

	if (spos == 0 && s->chars[spos] == c)
		s->chars[spos] = '\0';
}

size_t string_parse_rawhex(struct string *s, uint8_t *buf, size_t maxbytes)
{
	size_t length = strlen(s->chars);
	size_t bytes = length / 2;

	if (bytes == 0 || length % 2 != 0 || maxbytes < bytes)
		return 0;

	size_t x;
	for (x = 0; x < bytes; ++x)
	{
		char bs[3];
		bs[0] = s->chars[x * 2];
		bs[1] = s->chars[x * 2 + 1];
		bs[2] = '\0';

		unsigned int uib;

		if (sscanf(bs, "%x", &uib) != 1)
			return 0;

		buf[x] = (uint8_t) uib;
	}

	return bytes;
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
	if (root == 0)
		return (char*)path;

	char *newpath = strstr(path, root);

	if (newpath != path)
		return 0;

	newpath = newpath + strlen(root);

	if (*newpath == '/')
		return newpath + 1;
	else
		return 0;
}

void directoryentry_destroy(struct directoryentry *directory)
{
	string_free(directory->fullpath);
	string_free(directory->name);
}

struct directoryentrycollection *directoryentrycollection_new()
{
	struct directoryentrycollection *collection = malloc(sizeof(struct directoryentrycollection));
	if (collection == 0)
		fatalerror("out of memory!");

	collection->entries = malloc(sizeof(struct directoryentry));
	if (collection->entries == 0)
	{
		free(collection);
		fatalerror("out of memory!");
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
			fatalerror("out of memory!");

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

int getfiledigest(char *path, unsigned char *digest)
{
	FILE *stream = fopen(path, "rb");
	if (!stream)
		return 0;

	sha256 sha256_state;
	sha256_init(&sha256_state);

	struct BUFFEREDFILE *bf = bufferedfile_init(stream, ARCHIVE_BUFFER_SIZE);
	if (!bf)
	{
		fclose(stream);
		return 0;
	}

	uint8_t buf[ARCHIVE_BUFFER_SIZE];

	size_t read = bufferedfile_getbytes_unbuffered(buf, ARCHIVE_BUFFER_SIZE, bf);
	while (read > 0)
	{
		sha256_append(&sha256_state, buf, read);
		read = bufferedfile_getbytes_unbuffered(buf, ARCHIVE_BUFFER_SIZE, bf);
	}

	sha256_finalize_bytes(&sha256_state, digest);

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
		fatalerror("out of memory!");

	while (getcwd(buf, bufsize) == 0)
	{
		if (errno == ERANGE)
		{
			bufsize *= 2;

			char *newbuf = realloc(buf, bufsize);
			if (!newbuf)
			{
				free(buf);
				fatalerror("out of memory!");
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
	return ARCHIVE_OK;
}

ssize_t readarchive(struct archive *a, void *data, const void **buffer)
{
	struct libarchivedata *ldata = data;

	size_t read = bufferedfile_getbytes_unbuffered(ldata->buffer, ARCHIVE_BUFFER_SIZE, ldata->bstream);
	*buffer = ldata->buffer;

	return read;
}

int closearchive(struct archive *a, void *data)
{
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
		for (x = 0; x < SHA256_BYTES_SIZE; ++x)
			printf("%02x", de->hash[x]);

		printf(" ");
	}

	printf("%s\n", de->fullpath.chars);
}

int directoryentry_equalbydigest(const struct directoryentry *de1, const struct directoryentry *de2)
{
	int x;
	for (x = 0; x < SHA256_BYTES_SIZE; ++x)
		if (de1->hash[x] != de2->hash[x])
			return 0;

	return 1;
}

int directoryentry_comparebyfilename(const void *de1, const void *de2)
{
	const struct directoryentry *c1 = de1;
	const struct directoryentry *c2 = de2;

	return strcmp(c1->name.chars, c2->name.chars);
}

int directoryentry_getfromstring(struct string *s, struct directoryentry *entry, char *root)
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
				if (string_parse_rawhex(&signature, entry->hash, SHA256_BYTES_SIZE) != SHA256_BYTES_SIZE)
				{
					string_free(signature);
					return -1;
				}
				else
				{
					string_free(signature);

					entry->fullpath = string_fetchtoken(s, &offset, "");

					char *rpath = entry->fullpath.chars;

					if (root != 0)
						rpath = relativepath(entry->fullpath.chars, root);

					if (!rpath)
					{
						string_free(entry->fullpath);
						return 0;
					}

					entry->name = string_fromchars(rpath);

					return 1;
				}
			}
			else
			{
				string_free(signature);
				return -1;
			}
		}
		else if (strcmp(type.chars, "D") == 0) /* Directory. */
		{
			string_free(type);

			entry->type = DT_DIR;
			entry->fullpath = string_fetchtoken(s, &offset, "");

			char *rpath = entry->fullpath.chars;

			if (root != 0)
				rpath = relativepath(entry->fullpath.chars, root);

			if (!rpath)
			{
				string_free(entry->fullpath);
				return 0;
			}

			entry->name = string_fromchars(rpath);

			return 1;
		}
		else /* Unknown type. */
		{
			string_free(type);
			return -1;
		}
	}

	string_free(type);

	return 0;
}

void directoryentrycollection_sort(struct directoryentrycollection *collection)
{
	qsort(collection->entries, collection->length, sizeof(struct directoryentry), directoryentry_comparebyfilename);
}

void directoryentrycollection_compare(struct directoryentrycollection *c1, struct directoryentrycollection *c2, char *froot, char *troot)
{
	int differencesfound = 0;

	directoryentrycollection_sort(c1);
	directoryentrycollection_sort(c2);

	size_t c1pos = 0;
	size_t c2pos = 0;

	char *added_message = 0;
	char *removed_message = 0;
	char *modified_message = 0;

	if (!ISFLAG(flags, F_SHORTSUMMARY)) {
		added_message    = "   Added";
		removed_message  = " Removed";
		modified_message = "Modified";
	} else {
		added_message = "+";
		removed_message = "-";
		modified_message = "~";
	}

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
					printf("%s %s\n", modified_message, relativepath(c2->entries[c2pos].fullpath.chars, troot));
				}
			}
			else if (c1->entries[c1pos].type != c2->entries[c2pos].type)
			{
				differencesfound = 1;
				printf("%s %s\n", modified_message, relativepath(c2->entries[c2pos].fullpath.chars, troot));
			}

			c1pos++;
			c2pos++;
		}
		else if (cmp < 0)
		{
			differencesfound = 1;
			printf("%s %s\n", removed_message, relativepath(c1->entries[c1pos].fullpath.chars, froot));
			c1pos++;
		}
		else
		{
			differencesfound = 1;
			printf("%s %s\n", added_message, relativepath(c2->entries[c2pos].fullpath.chars, troot));
			c2pos++;
		}
	}

	if (c1pos < c1->length || c2pos < c2->length)
	{
		differencesfound = 1;

		while (c1pos < c1->length)
			printf("%s %s\n", removed_message, relativepath(c1->entries[c1pos++].fullpath.chars, froot));

		while (c2pos < c2->length)
			printf("%s %s\n", added_message, relativepath(c2->entries[c2pos++].fullpath.chars, troot));
	}

	if (!differencesfound)
		printf("No differences found.\n");
}

void directoryentrycollection_printhashes(struct directoryentrycollection *collection)
{
	printf("DIRHASH2\n");

	size_t e;
	for (e = 0; e < collection->length; ++e)
		directoryentry_print(collection->entries + e);
}

struct string path_append(const char *path, const char *name) {
	struct string s = string_fromchars("");

	if (path != 0 && strcmp(path, ".") != 0)
	{
		string_append(&s, path);
		string_append(&s, "/");
	}

	string_append(&s, name);

	return s;
}

int directoryentry_addfromfilesystem(struct directoryentrycollection *collection, char *path, char *root, char *verbosepath)
{
	DIR *cd;

	if (path != 0)
		cd = opendir(path);
	else
		cd = opendir(".");

	if (cd == 0)
	{
		warn("could not open %s", path);
		return 0;
	}

	int foundone = 0;

	struct dirent *dirinfo;
	while ((dirinfo = readdir(cd)) != 0)
	{
		if (strcmp(dirinfo->d_name, ".") == 0 || strcmp(dirinfo->d_name, "..") == 0)
			continue;

		if (dirinfo->d_type == DT_UNKNOWN) {
			struct stat st;

			struct string fullpath = path_append(path, dirinfo->d_name);

			if (stat(fullpath.chars, &st) != 0) {
				warn("could not read from '%s'", dirinfo->d_name);
				string_free(fullpath);
				continue;
			}

			if (S_ISREG(st.st_mode))
				dirinfo->d_type = DT_REG;
			else if (S_ISDIR(st.st_mode))
				dirinfo->d_type = DT_DIR;

			string_free(fullpath);
		}

		if (dirinfo->d_type != DT_DIR && dirinfo->d_type != DT_REG)
			continue;

		struct string s = path_append(path, dirinfo->d_name);

		char *rpath = s.chars;
		if (root != 0)
			rpath = relativepath(s.chars, root);

		if (dirinfo->d_type == DT_DIR)
		{
			if (rpath != 0)
			{
				struct string p = path_append(verbosepath, s.chars);

				if (ISFLAG(flags, F_VERBOSE))
					fprintf(stderr, "%s\n", p.chars);

				string_free(p);

				foundone = 1;

				struct directoryentry entry;
				entry.name = string_fromchars(rpath);
				entry.fullpath = string_fromchars(s.chars);
				entry.type = dirinfo->d_type;

				directoryentrycollection_add(collection, &entry);
			}

			foundone = directoryentry_addfromfilesystem(collection, s.chars, root, verbosepath) | foundone;
		}
		else if (rpath != 0) {
			struct string p = path_append(verbosepath, s.chars);

			if (ISFLAG(flags, F_VERBOSE))
				fprintf(stderr, "%s\n", p.chars);

			string_free(p);

			foundone = 1;

			struct directoryentry entry;
			entry.name = string_fromchars(rpath);
			entry.fullpath = string_fromchars(s.chars);
			entry.type = dirinfo->d_type;

			if (getfiledigest(s.chars, entry.hash))
			{
				directoryentrycollection_add(collection, &entry);
			}
			else
			{
				warn("error obtaining hash for %s", s.chars);
			}
		}

		string_free(s);
	}

	closedir(cd);

	return foundone;
}

struct directoryentrycollection *directoryentrycollection_getfromfilesystem(char *path, char *root)
{
	struct directoryentrycollection *collection = directoryentrycollection_new();
	if (!collection)
		fatalerror("out of memory!");

	char *cwd = mgetcwd();
	if (cwd == 0)
		fatalerror("could not determine current working directory!");

	if (chdir(path) != 0)
		fatalerror("could not chdir to %s!", path);

	const int foundone = directoryentry_addfromfilesystem(collection, 0, root, path);
	if (root && !foundone)
		fatalerror("subdirectory %s not found in %s", root, path);

	if (chdir(cwd) != 0)
		fatalerror("could not chdir to %s!", path);

	return collection;
}

struct directoryentrycollection *directoryentrycollection_getfromarchive(struct BUFFEREDFILE *bfile, char *path, char *root)
{
	struct directoryentrycollection *collection = directoryentrycollection_new();

	struct archive *a;
	struct archive_entry *entry;

	a = archive_read_new();
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);

	struct libarchivedata ldata;
	ldata.bstream = bfile;

	int foundone = 0;
	int archiveresult = 0;

	if (archive_read_open(a, &ldata, openarchive, readarchive, closearchive) != ARCHIVE_OK)
		fatalerror("error reading archive '%s'", path);

	while ((archiveresult = archive_read_next_header(a, &entry)) == ARCHIVE_OK)
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
				foundone = 1;

				if (ISFLAG(flags, F_VERBOSE))
					fprintf(stderr, "[%s] %s\n", path, s.chars);

				sha256 sha256_state;
				sha256_init(&sha256_state);

				uint8_t buf[8192];
				ssize_t read = archive_read_data(a, buf, 8192);
				while (read > 0)
				{
					sha256_append(&sha256_state, buf, read);

					read = archive_read_data(a, buf, 8192);
				}

				struct directoryentry direntry;
				direntry.name = string_fromchars(rpath);
				direntry.fullpath = string_fromchars(s.chars);
				direntry.type = DT_REG;

				sha256_finalize_bytes(&sha256_state, direntry.hash);

				directoryentrycollection_add(collection, &direntry);
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

			if (rpath != 0) {
				foundone = 1;

				if (ISFLAG(flags, F_VERBOSE))
					fprintf(stderr, "[%s] %s\n", path, s.chars);

				struct directoryentry direntry;
				direntry.name = string_fromchars(rpath);
				direntry.fullpath = string_fromchars(s.chars);
				direntry.type = DT_DIR;

				directoryentrycollection_add(collection, &direntry);
			}
			else {
				archive_read_data_skip(a);
			}

			string_free(s);
		}
		else {
			archive_read_data_skip(a);
		}
	}

	archive_read_close(a);
	archive_read_free(a);

	if (archiveresult != ARCHIVE_EOF)
		fatalerror("error reading archive '%s'", path);

	if (root && !foundone)
		fatalerror("directory %s not found in %s", root, path);

	return collection;
}

struct directoryentrycollection *directoryentrycollection_getfromhashfile(struct BUFFEREDFILE *bfile, char *path, char *root)
{
	struct directoryentry entry;

	uint8_t buf[10];
	if (bufferedfile_getbytes(buf, 9, bfile) == 9)
	{
		buf[9] = '\0';
		if (strcmp((char*)buf, "DIRHASH2\n") != 0) {
			bufferedfile_ungetbytes(bfile);
			return 0;
		}
		else {
			struct directoryentrycollection *collection = directoryentrycollection_new();

			size_t lineno = 1;
			struct string line = string_fromchars("");

			char c[2];
			c[1] = 0;

			int result = 0;
			int foundone = 0;

			while (bufferedfile_getbytes(c, 1, bfile) == 1)
			{
				switch (c[0])
				{
					case '\n':
						result = directoryentry_getfromstring(&line, &entry, root);

						if (result == 1) {
							foundone = 1;

							if (ISFLAG(flags, F_VERBOSE))
								fprintf(stderr, "[%s] %s\n", path, entry.fullpath.chars);

							directoryentrycollection_add(collection, &entry);
						}
						else if (result == -1) {
							fatalerror("hashfile contains errors in line %d:\n\"%s\"", lineno, line.chars);
						}

						++lineno;
						line.chars[0] = '\0';
						break;

					default:
						string_append(&line, c);
						break;
				}
			}

			string_free(line);

			if (root && !foundone)
				fatalerror("directory %s not found in %s", root, path);

			return collection;
		}
	}

	bufferedfile_ungetbytes(bfile);
	return 0;
}

int use_stdin(const char *path) {
	return strcmp(path, "-") == 0;
}

struct directoryentrycollection *directoryentrycollection_getfromfile(char *path, char *root)
{
	FILE *f;
	struct BUFFEREDFILE *bfile;
	struct directoryentrycollection *collection = 0;

	if (!use_stdin(path))
		f = fopen(path, "rb");
	else
		f = freopen(NULL, "rb", stdin);

	if (f != 0)
	{
		bfile = bufferedfile_init(f, ARCHIVE_BUFFER_SIZE);
		if (bfile)
		{
			collection = directoryentrycollection_getfromhashfile(bfile, path, root);

			if (!collection)
				collection = directoryentrycollection_getfromarchive(bfile, path, root);

			bufferedfile_destroy(bfile);
		}

		if (!use_stdin(path))
			fclose(f);
	}

	return collection;
}

void print_usage() {
	printf("Usage: dirchanges [options...] FROM [options...] [TO] [options...]\n");
}

void help_text()
{
	print_usage();
	printf("\n");

	//      0         10        20        30        40        50        60        70        80
	//------|---------|---------|---------|---------|---------|---------|---------|---------|-

	printf("Summarize differences between FROM and TO, where FROM and TO are directories,\n");
	printf("archives, or lists of hashes (as produced by the program).\n\n");

	printf(" -H --hash              read files in FROM and print a list of hashes to\n");
	printf("                        standard output for later use\n");
	printf(" -w --within=DIRECTORY  include only files appearing below DIRECTORY; this\n");
	printf("                        option applies to the preceding argument (FROM or TO)\n");
	printf("                        and, if used, must appear directly after it\n");
	printf(" -s --short             tag files added, removed or modified with +, -, ~\n");
	printf("                        instead of Added, Removed, and Modified\n");
	printf(" -v --verbose           verbosely list the files being processed\n");
	printf(" -V --version           print version number\n");
	printf(" -h --help              display this help message\n\n");
}

int main(int argc, char **argv)
{
	static struct getoptions_option opts[] = {
		{ "hash", 'H', 0, 'H' },
		{ "within", 'w', 1, 'w' },
		{ "verbose", 'v', 0, 'v' },
		{ "short", 's', 0, 's' },
		{ "version", 'V', 0, 'V' },
		{ "help", 'h', 0, 'h' },
		{ 0, 0, 0 }
	};

	program_name = argv[0];

	char *argument = 0;

	int option = 0;
	int optindex = 0;
	int currentarg = 0;
	int withinoptcount = 0;

	int errors = 0;

	char *dir_from = 0;
	char *dir_to = 0;
	char *within_from = 0;
	char *within_to = 0;

	int dir_from_position = 0;
	int dir_to_position = 0;

	while ((option = getoptions(argc, argv, opts, &argument, &optindex)) != GETOPTIONS_END) {
		++currentarg;

		switch (option) {
			case 'w':
				++withinoptcount;

				if (withinoptcount > 2) {
					warn("extra option '%s'", argv[optindex]);
					errors = 1;
				} else if (!dir_from) {
					warn("'%s' must follow the argument it applies to", argv[optindex]);
					errors = 1;
				} else if (!dir_to && withinoptcount == 2) {
					warn("'%s' must follow the argument it applies to", argv[optindex]);
					errors = 1;
				} else if (!dir_to && dir_from_position+1 != currentarg) {
					warn("'%s' must immediately follow the argument it applies to", argv[optindex]);
					errors = 1;
				} else if (dir_to && dir_to_position+1 != currentarg) {
					warn("'%s' must immediately follow the argument it applies to", argv[optindex]);
					errors = 1;
				} else {
					if (dir_to != 0) {
						within_to = argument;
					} else if (dir_from != 0) {
						within_from = argument;
					}
				}

				break;

			case 'v':
				SETFLAG(flags, F_VERBOSE);
				break;

			case 's':
				SETFLAG(flags, F_SHORTSUMMARY);
				break;

			case 'H':
				SETFLAG(flags, F_PRINTHASHES);
				break;

			case 'V':
				printf("%s %s\n", PROGRAM_NAME, DIRCHANGES_VERSION);
				exit(0);

			case 'h':
				help_text();
				exit(0);

			case GETOPTIONS_NONOPT:
			    if (dir_from == 0) {
					dir_from = argument;
					dir_from_position = currentarg;
				} else if (dir_to == 0) {
					dir_to = argument;
					dir_to_position = currentarg;
				} else {
					warn("extra argument '%s'", argument);
					errors = 1;
				}

				break;

			case GETOPTIONS_ERROR:
				errors = 1;
				break;
		}

		if (errors)
			break;
	}

	if (ISFLAG(flags, F_PRINTHASHES) && dir_to != 0) {
		warn("extra argument '%s'", dir_to);
		errors = 1;
	}

	if (!errors) {
		if (!ISFLAG(flags, F_PRINTHASHES)) {
			if (dir_from == 0 && dir_to == 0)
				errors = 1;
			else if (dir_to == 0)
				errors = 1;
		} else {
			if (dir_from == 0)
				errors = 1;
		}

		if (errors)
			print_usage();
	}

	if (errors) {
		fprintf(stderr, "Try '%s --help' for more information.\n", basename(argv[0]));
		return 0;
	}

	struct directoryentrycollection *collection1 = 0;
	struct directoryentrycollection *collection2 = 0;

	struct stat f1stat;
	struct stat f2stat;

	if (dir_from && use_stdin(dir_from) && dir_to && use_stdin(dir_to))
		fatalerror("cannot read twice from stdin");

	if (!use_stdin(dir_from) && stat(dir_from, &f1stat) != 0)
		fatalerror("unable to read or open '%s'", dir_from);

	if (S_ISDIR(f1stat.st_mode)) {
		collection1 = directoryentrycollection_getfromfilesystem(dir_from, within_from);
	} else if (S_ISREG(f1stat.st_mode) || use_stdin(dir_from)) {
		collection1 = directoryentrycollection_getfromfile(dir_from, within_from);
	} else {
		fatalerror("%s is not a file or directory", dir_from);
	}

	if (dir_to) {
		if (!use_stdin(dir_to) && stat(dir_to, &f2stat) != 0)
			fatalerror("unable to read or open '%s'", dir_to);

		if (S_ISDIR(f2stat.st_mode)) {
			collection2 = directoryentrycollection_getfromfilesystem(dir_to, within_to);
		} else if (S_ISREG(f2stat.st_mode) || use_stdin(dir_to)) {
			collection2 = directoryentrycollection_getfromfile(dir_to, within_to);
		} else {
			fatalerror("%s is not a file or directory", dir_to);
		}
	}

	if (ISFLAG(flags, F_VERBOSE))
		fprintf(stderr, "\n");

	if (ISFLAG(flags, F_PRINTHASHES))
		directoryentrycollection_printhashes(collection1);
	else
		directoryentrycollection_compare(collection1, collection2, within_from, within_to);

	if (collection2)
		directoryentrycollection_free(collection2);

	directoryentrycollection_free(collection1);

	return 0;
}

