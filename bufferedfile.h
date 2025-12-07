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

#ifndef BUFFEREDFILE_H
#define BUFFEREDFILE_H

#include <stdio.h>
#include <stdint.h>

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

struct BUFFEREDFILE *bufferedfile_init(FILE *stream, size_t maxlookahead);
void bufferedfile_destroy(struct BUFFEREDFILE *f);
size_t bufferedfile_getbytes(void *buf, size_t count, struct BUFFEREDFILE *file);
size_t bufferedfile_getbytes_unbuffered(void *buf, size_t count, struct BUFFEREDFILE *file);
void bufferedfile_ungetbytes(struct BUFFEREDFILE *file);
int bufferedfile_seek(long offset, int whence, struct BUFFEREDFILE *file);

#endif