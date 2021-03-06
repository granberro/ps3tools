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
#include <sys/stat.h>

static u8 *pkg = NULL;
static PKG_HEADER pkg_header;


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

static void unpack_pkg(void)
{
	u32 i;
	u32 fname_len;
	u32 fname_off;
	u64 file_offset;
	u32 flags;
	char fname[256];
	u8 *tmp;
	u64 file_size;

	for (i = 0; i < pkg_header.file_count; i++) {
		tmp = pkg + pkg_header.offset + i*0x20;

		fname_off = be32(tmp) + pkg_header.offset;
		fname_len = be32(tmp + 0x04);
		file_offset = be64(tmp + 0x08) + pkg_header.offset;
		file_size = be64(tmp + 0x10);
		flags = be32(tmp + 0x18);

		if (fname_len >= sizeof fname)
			fail("filename too long: %s", pkg + fname_off);

		memset(fname, 0, sizeof fname);
		strncpy(fname, (char *)(pkg + fname_off), fname_len);

		flags &= 0xff;

		printf("File Type:    %04x - %s\n", flags, id2name(flags, t_file_type, "unknown"));
		printf("  Name:         %s\n", fname);
		printf("  size:       %08x_%08x bytes\n", (u32)(file_size>>32), (u32)file_size);

		if (flags == 4)
			mkdir(fname, 0777);
		else if (flags == 1 || flags == 3 || flags == 9 || flags == 2)
			memcpy_to_file(fname, pkg + file_offset, file_size);
		else
			fail("unknown flags: %08x", flags);
	}
}

int main(int argc, char *argv[])
{
	char *dir;
	FILE *decrypted;

	if (argc != 2 && argc != 3 && argc != 4)
		fail("usage: ungpkg filename.pkg [target] [decryted]");

	pkg = mmap_file(argv[1]);

	if (argc == 2) {
		dir = malloc(0x31);
		memset(dir, 0, 0x31);
		memset(dir, 0, 0x30);
		memcpy(dir, pkg + 0x30, 0x30);
	} else {
		dir = argv[2];
	}

	mkdir(dir, 0777);

	if (chdir(dir) != 0)
		fail("chdir(%s)", dir);

	parse_header();

	if (pkg_header.type & PKG_RETAIL)
		decrypt_retail_pkg();
	else 
		if (pkg_header.type & PKG_DEBUG)
			decrypt_debug_pkg();
	else 
		fail("invalid pkg type: %x", pkg_header.type);

	if (argc == 4) {
		decrypted = fopen (argv[3], "wb");
  		if (decrypted == NULL)
    		fail ("Can't open output file");

		fwrite(pkg + pkg_header.offset, pkg_header.size, 1, decrypted);
		fclose(decrypted);	
	}

	unpack_pkg();

	return 0;
}
