/* bufferedfile Copyright (c) 2025 Adrian Lopez

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

#define  _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <err.h>
#include "bufferedfile.h"

#define MAX(X, Y) (X > Y ? X : Y)
#define MIN(X, Y) (X < Y ? X : Y)

struct BUFFEREDFILE *bufferedfile_init(FILE *stream, size_t maxlookahead)
{
	struct BUFFEREDFILE *f = malloc(sizeof(struct BUFFEREDFILE));
	if (!f)
		errx(1, "out of memory!");

	f->buffer = malloc(maxlookahead * 2);
	if (!f->buffer) {
		free(f);
		errx(1, "out of memory!");
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

int bufferedfile_intersection(uint64_t *i0, uint64_t *i1, uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1)
{
	if (a1 <= b0 || b1 <= a0)
		return 0;

	*i0 = MAX(a0, b0);
	*i1 = MIN(a1, b1);

	return 1;
}

size_t bufferedfile_getbytes_(void *buf, size_t count, struct BUFFEREDFILE *file, int buffered)
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
	if (bufferedfile_intersection(&i0, &i1, file->fpos, file->fpos + count, file->buffer0start, file->buffer0end))
	{
		/* Copy contents from buffer 0 onto target buf. */
		if (file->buffer0start <= i0)
			memcpy(buf, file->buffer + (size_t)(i0 - file->buffer0start), (size_t)(i1 - i0));
		else
			memcpy(buf + (size_t)(file->buffer0start - i0), file->buffer, (size_t)(i1 - i0));

		bytesread += (size_t)(i1 - i0);
	}

	/* Does read operation include data from buffer 1? */
	if (bufferedfile_intersection(&i0, &i1, file->fpos, file->fpos + count, file->buffer1start, file->buffer1end))
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
	return bufferedfile_getbytes_(buf, count, file, 1);
}

size_t bufferedfile_getbytes_unbuffered(void *buf, size_t count, struct BUFFEREDFILE *file)
{
	return bufferedfile_getbytes_(buf, count, file, 0);
}

void bufferedfile_ungetbytes(struct BUFFEREDFILE *file)
{
	file->fpos = file->rollback;
}

int bufferedfile_seek(long offset, int whence, struct BUFFEREDFILE *file)
{
	if (fseeko(file->stream, offset, whence) == 0)
	{
		off_t newpos = 0;

		switch (whence) {
			case SEEK_SET:
				file->fpos = offset;
				break;

			case SEEK_CUR:
				file->fpos += offset;
				break;

			case SEEK_END:
				newpos = ftello(file->stream);
				if (newpos == -1)
					return 0;

				file->fpos = newpos;

				break;
		}

		file->eof = 0;
		file->error = 0;
		file->rollback = file->fpos;
		file->buffer0start = file->fpos;
		file->buffer0end = file->fpos;
		file->buffer1start = file->fpos;
		file->buffer1end = file->fpos;

		return 1;
	}

	return 0;
}