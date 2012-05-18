/*
  # ../norunpkg norflash.bin norflash
  unpacking asecure_loader (size: 190xxx bytes)...
  unpacking eEID (size: 65536 bytes)...
  unpacking cISD (size: 2048 bytes)...
  unpacking cCSD (size: 2048 bytes)...
  unpacking trvk_prg0 (size: 131072 bytes)...
  unpacking trvk_prg1 (size: 131072 bytes)...
  unpacking trvk_pkg0 (size: 131072 bytes)...
  unpacking trvk_pkg1 (size: 131072 bytes)...
  unpacking ros0 (size: 7340032 bytes)...
  unpacking ros1 (size: 7340032 bytes)...
  unpacking cvtrm (size: 262144 bytes)...
*/

// Copyright 2010       Sven Peter
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
// nor modifications by rms.

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef WIN32
#define MKDIR(x,y) mkdir(x)
#else
#define MKDIR(x,y) mkdir(x,y)
#endif

u8 *pkg = NULL;

static void unpack_file(u32 i)
{
        u8 *ptr;
        u8 name[33];
        u64 offset;
        u64 size;

        ptr = pkg + 0x10 + 0x30 * i;

        offset = be64(ptr + 0x00);
        size   = be64(ptr + 0x08);

        memset(name, 0, sizeof name);
        strncpy((char *)name, (char *)(ptr + 0x10), 0x20);

        printf("unpacking %s (size: %d bytes)...\n", name, size);
        memcpy_to_file((char *)name, pkg + offset, size);
}

static void unpack_pkg(void)
{
        u32 n_files;
        u64 size;
        u32 i;

        n_files = be32(pkg + 4);
        size = be64(pkg + 8);

        for (i = 0; i < n_files; i++)
                unpack_file(i);
}

int main(int argc, char *argv[])
{
        if (argc != 3)
                fail("usage: nandunpack filename.bin target");

        pkg = mmap_file(argv[1]);

        /* kludge for header, i do not do sanity checks at the moment */
        pkg += 0x200;

        MKDIR(argv[2], 0777);

        if (chdir(argv[2]) != 0)
                fail("chdir");

        unpack_pkg();

        return 0;
}
