// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define	MAX_SECTIONS	255

static u8 *self = NULL;
static u8 *elf = NULL;
static FILE *out = NULL;

static u64 info_offset;
static u32 key_ver;
static u64 phdr_offset;
static u64 shdr_offset;
static u64 sec_offset;
static u64 ver_offset;
static u64 control_offset;
static u64 version;
static u64 elf_offset;
static u64 meta_offset;
static u64 header_len;
static u64 filesize;
static u32 arch64;
static u32 n_sections;
static struct keylist *klist;

static struct elf_hdr ehdr;
static struct key ks;

static u32 app_type;

static struct {
	u32 offset;
	u32 size;
	u32 compressed;
	u32 size_uncompressed;
	u32 elf_offset;
} self_sections[MAX_SECTIONS];

static void read_header(void)
{
	key_ver =    be16(self + 0x08);
	meta_offset = be32(self + 0x0c);
	header_len =  be64(self + 0x10);
	filesize =    be64(self + 0x18);
	info_offset = be64(self + 0x28);
	elf_offset =  be64(self + 0x30);
	phdr_offset = be64(self + 0x38) - elf_offset;
	shdr_offset = be64(self + 0x40) - elf_offset;
	sec_offset =  be64(self + 0x48);
	ver_offset =  be64(self + 0x50);
	control_offset =  be64(self + 0x58);

	version =   be64(self + info_offset + 0x10);
	app_type =    be32(self + info_offset + 0x0c);

	elf = self + elf_offset;
	arch64 = elf_read_hdr(elf, &ehdr);
}

struct self_sec {
	
	u32 idx;
	u64 offset;
	u64 size;
	u32 compressed;
	u32 encrypted;
	u64 next;
};

static void get_keys(enum sce_key type, const char *suffix)
{
	if (key_get(type, suffix, &ks) < 0)
		fail("key_get failed");

	if (ks.pub_avail < 0)
		fail("no public key available");

	if (ks.priv_avail < 0)
		fail("no private key available");

	if (ecdsa_set_curve(ks.ctype) < 0)
		fail("ecdsa_set_curve failed");

	ecdsa_set_pub(ks.pub);
	ecdsa_set_priv(ks.priv);
}


static struct keylist *self_load_keys(void)
{
	enum sce_key id;

	switch (app_type) {
		case 1:
			id = KEY_LV0;
			break;
	 	case 2:
			id = KEY_LV1;
			break;
		case 3:
			id = KEY_LV2;
			break;
		case 4:	
			id = KEY_APP;
			break;
		case 5:
			id = KEY_ISO;
			break;
		case 6:
			id = KEY_LDR;
			break;
		case 8:
            		id = KEY_NPDRM;
			break;
		default:
			fail("invalid type: %08x", app_type);	
	}

	return keys_get(id);
}

static void read_section(u32 i, struct self_sec *sec)
{
	u8 *ptr;

	ptr = self + sec_offset + i*0x20;

	sec->idx = i;
	sec->offset     = be64(ptr + 0x00);
	sec->size       = be64(ptr + 0x08);
	sec->compressed = be32(ptr + 0x10) == 2 ? 1 : 0;
	sec->encrypted  = be32(ptr + 0x1c);
	sec->next       = be64(ptr + 0x20);
}

static int qsort_compare(const void *a, const void *b)
{
	const struct self_sec *sa, *sb;
	sa = a;
	sb = b;

	if (sa->offset > sb->offset)
		return 1;
	else if(sa->offset < sb->offset)
		return -1;
	else
		return 0;
}

static void read_sections(void)
{
	struct self_sec s[MAX_SECTIONS];
	struct elf_phdr p;
	u32 i;
	u32 j;
	u32 n_secs;
	u32 self_offset, elf_offset;

	memset(s, 0, sizeof s);
	for (i = 0, j = 0; i < ehdr.e_phnum; i++) {
		read_section(i, &s[j]);
		if (s[j].size) {
			elf_read_phdr(arch64, elf + phdr_offset + (ehdr.e_phentsize * s[j].idx), &p);
			if (p.p_type == 0x700000A4 || p.p_type == 1)
				j++;
		}
	}

	n_secs = j;
	qsort(s, n_secs, sizeof(*s), qsort_compare);

	elf_offset = 0;
	self_offset = header_len;
	j = 0;
	i = 0;

	while (elf_offset < filesize) {

		if (i == n_secs) {
			self_sections[j].offset = self_offset;
			self_sections[j].size = filesize - elf_offset;
			self_sections[j].compressed = 0;
			self_sections[j].size_uncompressed = filesize - elf_offset;
			self_sections[j].elf_offset = elf_offset;
			elf_offset = filesize;
		} else if (self_offset == s[i].offset) {
			elf_read_phdr(arch64, elf + phdr_offset + (ehdr.e_phentsize * s[i].idx), &p);
			self_sections[j].offset = self_offset;
			self_sections[j].size = s[i].size;
			self_sections[j].compressed = s[i].compressed;
			self_sections[j].size_uncompressed = p.p_filesz;
			self_sections[j].elf_offset = p.p_off;
			elf_offset = p.p_off + self_sections[j].size_uncompressed;
			self_offset = s[i].next;
			i++;
		} else {
			elf_read_phdr(arch64, elf + phdr_offset + (ehdr.e_phentsize * s[i].idx), &p);
			self_sections[j].offset = self_offset;
			self_sections[j].size = p.p_off - elf_offset;
			self_sections[j].compressed = 0;
			self_sections[j].size_uncompressed = self_sections[j].size;
			self_sections[j].elf_offset = elf_offset;

			elf_offset += self_sections[j].size;
			self_offset += s[i].offset - self_offset;
		}
		j++;
	}

	n_sections = j;
}

static void write_elf(void)
{
	u32 i;
	u32 meta_n_hdr;
	u8 *bfr;
	u8 patched;

	patched = 0;

	if (key_ver != 0x8000)
		meta_n_hdr = be32(self + meta_offset + 0x60 + 0xc);
	else
		meta_n_hdr = ehdr.e_phnum;

	for (i = 0; i < n_sections; i++) {

		// Compressed
		if (self_sections[i].compressed) {
			if (self_sections[i].size_uncompressed) {
				bfr = malloc(self_sections[i].size_uncompressed);
				decompress(self + self_sections[i].offset,
					   self_sections[i].size,
					   bfr, self_sections[i].size_uncompressed);

				patched = patch_sdk(self_sections[i].size_uncompressed, bfr);
			  
				if (patched) {
					free(bfr);
					fail("compress!!!");
					break;
				}
				free(bfr);
			}
		}
		else {
			if (self_sections[i].size) {
				bfr = self + self_sections[i].offset;

				patched = patch_sdk(self_sections[i].size, bfr);
			  
				if (patched) {
					break;
				}
			}
		}
	}

	if (patched) {
		u8 *hashes;
		u8 *r, *s;
		u8 hash[20];
		u64 sig_len;

		// key version
		wbe16(self + 0x08, 01);
		header_len -= 0x100;
		//wbe64(self + 0x60, be64(self + 0x60) - 0x90);
		wbe32(self + info_offset + 0x0c, 0x04);

		// SCE Version Info file
		wbe32(self + ver_offset + 0x6c, 0x00);

		get_keys(KEY_APP, "315");

		printf("Hashing section %d\n", i);
		hashes = self + meta_offset + 0x80 + 0x30 * meta_n_hdr;
		memset(hashes + (i * 8 * 0x10), 0, 0x20);
		sha1_hmac(hashes + ((i * 8) + 2) * 0x10,
		          self + self_sections[i].offset,
			  self_sections[i].size,
			  hashes + (i * 8) * 0x10);

		sig_len = be64(self + meta_offset + 0x60);
		r = self + sig_len;
		s = r + 21;
		sha1(self, sig_len, hash);
		ecdsa_sign(hash, r, s);

		printf("Encrypting data\n");
		if (sce_encrypt_data(self) < 0)
			fail("self_encrypt_data failed");

		printf("Saving encrypted data\n");
		bfr = self + self_sections[i].offset;
print_hash(bfr, 0x10);
printf("\n");
		//fseek (out, self_sections[i].offset - 0x100, SEEK_SET);
		fseek (out, self_sections[i].offset, SEEK_SET);
		fwrite(bfr, self_sections[i].size, 1, out);

		printf("Encrypting header\n");
		wbe64(self + 0x10, header_len);
		if (sce_encrypt_header(self, &ks) < 0)
			fail("self_encrypt_header failed");

		//wbe32(self + 0x0c, meta_offset - 0x90);		

		printf("Saving header\n");
		bfr = self;
		fseek(out, 0 , SEEK_SET);
		fwrite(bfr, header_len , 1, out);
		//fwrite(bfr, 0x430 , 1, out);
		//fwrite(bfr + 0x4C0, header_len - 0x4C0 , 1, out);
	}

close(out);
return;

}

static void self_decrypt(void)
{
	klist = self_load_keys();
	if (klist == NULL)
		fail("no key found");

	if (sce_remove_npdrm(self, klist) < 0)
	        fail("self_remove_npdrm failed");

	if (sce_decrypt_header(self, klist) < 0)
		fail("self_decrypt_header failed");

	if (sce_decrypt_data(self) < 0)
		fail("self_decrypt_data failed");
}

int main(int argc, char *argv[])
{
	u64 size;

	if (argc < 3 || argc > 5)
		fail("usage: patchself2 in.self out.self");

	self = mmap_file(argv[1]);

	if (be32(self) != 0x53434500)
		fail("not a SELF");

	size = get_filesize(argv[1]);

	out = fopen(argv[2], "wb");
	fwrite(self, size, 1, out);
	//fwrite(self, 0x430, 1, out);
	//fwrite(self+ 0x4C0 + 0x70, size-0x04C0 - 0x70, 1, out);
	fclose(out);

	read_header();
	read_sections();

	if (key_ver != 0x8000)
		self_decrypt();

	out = fopen(argv[2], "rb+");

	write_elf();

	fclose(out);

	return 0;
}
