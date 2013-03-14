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

#define F_PRINTHASHES 0x0001

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

struct libarchivedata
{
	struct string name;
	FILE *archive;
	unsigned char buffer[ARCHIVE_BUFFER_SIZE];	
};

struct string string_fromchars(const char *chars)
{
	struct string s;
	s.allocated = strlen(chars) + 1;
	s.chars = malloc(s.allocated);

	if (s.chars == 0)
		s.allocated = 0;

	strcpy(s.chars, chars);

	return s;
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

void string_free(struct string s)
{
	free(s.chars);
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
		exit(1);

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

void getfiledigest(char *path, uint8_t *digest)
{
	SHA1_CTX sha1ctx;

	SHA1_Init(&sha1ctx);
	
	FILE *f = fopen(path, "rb");
	
	uint8_t buf[ARCHIVE_BUFFER_SIZE];

	size_t read = fread(buf, sizeof(uint8_t), ARCHIVE_BUFFER_SIZE, f);
	while (read > 0)
	{
		SHA1_Update(&sha1ctx, buf, read);
		read = fread(buf, sizeof(uint8_t), ARCHIVE_BUFFER_SIZE, f);
	}

	SHA1_Final(&sha1ctx, digest);

	fclose(f);
}

char *mgetcwd()
{
	char *buf;
	size_t bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf)
		return 0;

	while (getcwd(buf, bufsize) == 0)
	{
		if (errno == ERANGE)
		{
			bufsize *= 2;
			
			char *newbuf = realloc(buf, bufsize);
			if (!newbuf)
			{
				free(buf);
				return 0;
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
		ldata->archive = fopen(ldata->name.chars, "rb");
	}
	else
	{
		freopen(NULL, "rb", stdin);
		ldata->archive = stdin;
	}

	if (!ldata->archive)
		return ARCHIVE_FATAL;

	return ARCHIVE_OK;
}

ssize_t readarchive(struct archive *a, void *data, const void **buffer)
{
	struct libarchivedata *ldata = data;

	size_t read = fread(ldata->buffer, 1, ARCHIVE_BUFFER_SIZE, ldata->archive);
	*buffer = ldata->buffer;

	return read;
}

int closearchive(struct archive *a, void *data)
{
	struct libarchivedata *ldata = data;

	if (strcmp(ldata->name.chars, "-") != 0)
		fclose(ldata->archive);

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

	printf("%s\n", de->name.chars);
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
			getfiledigest(s.chars, entry.sha1);

			directoryentrycollection_add(collection, &entry);

			fprintf(stderr, "%s\n", s.chars);	
		}
		//else
		//{
		//	fprintf(stderr, "skipping %s\n", s.chars);
		//}

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
		
				fprintf(stderr, "%s\n", s.chars);	
			}
			else
			{
				//fprintf(stderr, "skipping %s\n", s.chars);
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
		
				fprintf(stderr, "%s\n", s.chars);	
			}
			else
			{
				//fprintf(stderr, "skipping %s\n", s.chars);
				archive_read_data_skip(a);
			}

			string_free(s);
		}
		else
		{
			struct string s = string_fromchars(archive_entry_pathname(entry));
			string_removetrailingcharacter(&s, '/');

			//fprintf(stderr, "skipping %s\n", s.chars);
			archive_read_data_skip(a);

			string_free(s);
		}
	}

	archive_read_close(a);
	archive_read_free(a);

	string_free(ldata.name);

	return collection;
}

int main(int argc, char **argv)
{	
	static struct option long_options[] = 
	{
		{ "froot", 1, 0, 'f' },
		{ "troot", 1, 0, 't' },
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

		case '?':
			errors = 1;
			break;
		}
	}

	int nonoptc = argc - optind;
	if (nonoptc < 1)
	{
		fprintf(stderr, "%s: must specify FROM parameter.\n", argv[0]);
		errors = 1;
	}

	if (nonoptc < 2)
	{
		fprintf(stderr, "%s: must specify TO parameter.\n", argv[0]);
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

	if (strcmp(argv[optind], "-") == 0 || S_ISREG(f1stat.st_mode))
	{
		fprintf(stderr, "Reading from archive \"%s\"...\n", argv[optind]);
		collection1 = directoryentrycollection_getfromarchive(argv[optind], froot);
	}
	else if (S_ISDIR(f1stat.st_mode))
	{
		fprintf(stderr, "Reading from directory \"%s\"...\n", argv[optind]);
		collection1 = directoryentrycollection_getfromfilesystem(argv[optind], froot);
	}

	if (strcmp(argv[optind+1], "-") == 0 || S_ISREG(f2stat.st_mode))
	{
		fprintf(stderr, "\nReading from archive \"%s\"...\n", argv[optind+1]);
		collection2 = directoryentrycollection_getfromarchive(argv[optind+1], troot);
	}
	else if (S_ISDIR(f2stat.st_mode))
	{
		fprintf(stderr, "\nReading from directory \"%s\"...\n", argv[optind+1]);
		collection2 = directoryentrycollection_getfromfilesystem(argv[optind+1], troot);
	}

	fprintf(stderr, "\n");

	if (ISFLAG(flags, F_PRINTHASHES))
		directoryentrycollection_printhashes(collection1, argv[optind]);
	else
		directoryentrycollection_compare(collection1, collection2, argv[optind], argv[optind+1]);
	
	directoryentrycollection_free(collection2);
	directoryentrycollection_free(collection1);

	return 0;
}

