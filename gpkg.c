// Copyright 2010-2011 Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

// Thanks to Mathieulh for his C# retail unpacker
//  (http://twitter.com/#!/Mathieulh/status/23070344881381376)
// Thanks to Matt_P for his python debug unpacker
//  (https://github.com/HACKERCHANNEL/PS3Py/blob/master/pkg.py)

#include "tools.h"
#include "types.h"
#include "common.h"
#include "gpkg.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define	MAX_FILES	255
static u8 *pkg = NULL;
static u8 *destpkg = NULL;
static PKG_HEADER pkg_header;
static u32 n_files = 0;
static struct pkg_file files[MAX_FILES];

static void get_files(const char *d)
{
	DIR *dir;
	struct dirent *de;
	struct stat st;
	char path[256];
	u32 i;
	u64 offset;

	dir = opendir(d);
	if (dir == NULL)
		fail("opendir");

	offset = 0;
	i = 0;
	while ((de = readdir(dir))) {
		if (n_files == MAX_FILES)
			fail("file overflow. increase MAX_FILES");

		if (strcmp(de->d_name, ".") == 0)
			continue;

		if (strcmp(de->d_name, "..") == 0)
			continue;
		
		if (strlen(de->d_name) > 0x20)
			fail("name too long: %s", de->d_name);

//		if (de->d_type != DT_REG)
//			fail("not a file: %s, %i", de->d_name, de->d_type);

		snprintf(path, sizeof path, "%s/%s", d, de->d_name);

		printf("file:     %s %d\n", de->d_name ,de->d_type);

		memset(&files[i], 0, sizeof(*files));
		strncpy(files[i].name, de->d_name, 0x19);

		if (stat(path, &st) < 0)
			fail("cannot stat %s %d", path, stat(path, &st));
		files[i].size = st.st_size;

		files[i].ptr = mmap_file(path);
		if (files[i].ptr == NULL)
			fail("unable to mmap %s", path);

		files[i].offset = offset;
		offset = round_up(offset + files[i].size, 0x20);
	
		i++;
		n_files++;
	}
}

static void parse_header()
{
	memcpy(&pkg_header, pkg, sizeof(pkg_header));
	pkg_header.type = be32(pkg + 0x04); 
	pkg_header.info_offset = be32(pkg + 0x08); 
	pkg_header.info_size = be32(pkg + 0x0C); 
	pkg_header.header_size = be32(pkg + 0x10);
	pkg_header.file_count = be32(pkg + 0x14);
	pkg_header.pkg_size = be64(pkg + 0x18);
	pkg_header.offset = be64(pkg + 0x20);
	pkg_header.size = be64(pkg + 0x28);
	memcpy(pkg_header.title_id , pkg + 0x30, sizeof(pkg_header.title_id));
	memcpy(pkg_header.qa_digest , pkg + 0x60, sizeof(pkg_header.qa_digest));
	memcpy(pkg_header.enc_licence , pkg + 0x70, sizeof(pkg_header.enc_licence));
	memcpy(pkg_header.key2 , pkg + 0x80, sizeof(pkg_header.key2));
	memcpy(pkg_header.hash_of_key2 , pkg + 0x90, sizeof(pkg_header.hash_of_key2));
	memcpy(pkg_header.hash_of_key2_1 , pkg + 0xA0, sizeof(pkg_header.hash_of_key2_1));
	memcpy(pkg_header.hash_of_key2_2 , pkg + 0xB0, sizeof(pkg_header.hash_of_key2_2));

	printf("Pkg type:         %08x\n", pkg_header.type);
	printf("  Id:             %s\n", pkg_header.title_id);
	printf("  info offet:     %04x\n", pkg_header.info_offset);
	printf("  info size:      %04x\n", pkg_header.info_size*8);
	printf("  header size:    %04x\n", pkg_header.header_size);
	printf("  files:          %d\n", pkg_header.file_count);
	printf("  total size:     %08x_%08x bytes\n", (u32)(pkg_header.pkg_size>>32), (u32)pkg_header.pkg_size);
	printf("  date_size:      %08x_%08x bytes\n", (u32)(pkg_header.size>>32), (u32)pkg_header.size);
	printf("  data_offset:    %08x_%08x bytes\n", (u32)(pkg_header.offset>>32), (u32)pkg_header.offset);
}

static void decrypt_retail_pkg(void)
{
	u8 key[0x10];
	u8 iv[0x10];

	if (key_get_simple("gpkg-key", key, 0x10) < 0)
		fail("failed to load the package key.");

	memcpy(iv, pkg + 0x70, 0x10);
	aes128ctr(key, iv, pkg + pkg_header.offset, pkg_header.size, pkg + pkg_header.offset);
}

static void decrypt_debug_pkg(void)
{
	u8 key[0x40];
	u8 bfr[0x1c];
	u64 i;

	memset(key, 0, sizeof key);
	memcpy(key, pkg + 0x60, 8);
	memcpy(key + 0x08, pkg + 0x60, 8);
	memcpy(key + 0x10, pkg + 0x60 + 0x08, 8);
	memcpy(key + 0x18, pkg + 0x60 + 0x08, 8);

	sha1(key, sizeof key, bfr);

	for (i = 0; i < pkg_header.size; i++) {
		if (i != 0 && (i % 16) == 0) {
			wbe64(key + 0x38, be64(key + 0x38) + 1);	
			sha1(key, sizeof key, bfr);
		}
		pkg[pkg_header.offset + i] ^= bfr[i & 0xf];
	}
}

static void get_files_pkg(const char *d)
{
	u32 i;
	u64 running_offset;
	u8 *tmp;
	u64 total_size;
	char path[256];
	struct stat st;
	u32 flags;

	total_size = 0;
	tmp = pkg + pkg_header.offset;
	running_offset = be64(tmp + 0x08) + pkg_header.offset;

	for (i = 0; i < pkg_header.file_count; i++) {
		tmp = pkg + pkg_header.offset + i*0x20;

		files[i].name_offset = be32(tmp) + pkg_header.offset;
		files[i].name_len = be32(tmp + 0x04);
		files[i].offset = running_offset;
		files[i].flags = be32(tmp + 0x18);
		memset(files[i].name, 0, sizeof files[i].name);
		strncpy(files[i].name, (char *)(pkg + files[i].name_offset), files[i].name_len);

		//snprintf(path, sizeof path, "%s/%s", d, files[i].name);
		
		//stat(path, &st);
		//files[i].size = st.st_size;
		//running_offset+= files[i].size;
		//total_size+= files[i].size;
		//files[i].ptr = mmap_file(path);
		//if (files[i].ptr == NULL)
		//	fail("unable to mmap %s", path);

		printf("  Id:         %d\n", i);
		printf("  header:     %s\n", files[i].name);
		printf("  size:       %08x_%08x bytes\n", (u32)(files[i].size>>32), (u32)files[i].size);

		//file_size = be64(tmp + 0x10);
		flags = be32(tmp + 0x18);
		flags &= 0xff;

		printf("File Type:    %04x \n", flags);
		//printf("  Name:         %s\n", fname);
		//printf("  size:       %08x_%08x bytes\n", (u32)(file_size>>32), (u32)file_size);

/*		if (flags == 4)
			mkdir(fname, 0777);
		else if (flags == 1 || flags == 3 || flags == 9 || flags == 2)
			memcpy_to_file(fname, pkg + file_offset, file_size);
		else
			fail("unknown flags: %08x", flags);*/
	}
}

int main(int argc, char *argv[])
{
	u32 i;

	if (argc != 3 && argc != 4)
		fail("usage: gpkg contents filename.pkg [original.pkg]");

	if (argc == 4) 
		destpkg = mmap_file(argv[3]);

	pkg = mmap_file(argv[2]);
	parse_header();

	if (pkg_header.type & PKG_RETAIL)
		decrypt_retail_pkg();
	else 
		if (pkg_header.type & PKG_DEBUG)
			decrypt_debug_pkg();
	else 
		fail("invalid pkg type: %x", pkg_header.type);
	
/*	get_files_pkg(argv[1]);

	for (i=0; i<n_files;i++) {
		printf("  Id:         %d\n", i);
		printf("  header:     %s\n", files[i].name);
		printf("  size:       %08x_%08x bytes\n", (u32)(files[i].size>>32), (u32)files[i].size);
	}

       foo = fopen(argv[3], "wb");
		fwrite(pkg + pkg_header.offset, pkg_header.size, 1, foo);
*/
	return 0;
}
