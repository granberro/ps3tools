/*
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 2, as published by the Free Software Foundation.
 */

#include "tools.h"
#include "self.h"
#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static FILE *keypair;
static u8 patch = 0;

int main(int argc, char *argv[])
{
  FILE *in;
  FILE *out;
  SELF self;
  APP_INFO app_info;
  ELF elf;
  ELF_PHDR *phdr;
  ELF_SHDR *shdr;
  SECTION_INFO *section_info;
  SCEVERSION_INFO sceversion_info;
  CONTROL_INFO *control_info;
  METADATA_INFO metadata_info;
  METADATA_HEADER metadata_header;
  METADATA_SECTION_HEADER *section_headers;
  uint8_t *keys;
  SIGNATURE_INFO signature_info;
  SIGNATURE signature;
  SELF_SECTION *sections;
  int num_sections;
  int i;

  if (argc < 3 || argc > 5) {
    fprintf(stderr, "usage: %s in.self out.elf [keypair [patch]]\n", argv[0]);
    return -1;
  }

  in = fopen (argv[1], "rb");
  if (in == NULL) {
    ERROR (-2, "Can't open input file");
  }

  self_read_headers(in, &self, &app_info, &elf, &phdr, &shdr,
      &section_info, &sceversion_info, &control_info);

  self_read_metadata (in, &self, &app_info, &metadata_info,
      &metadata_header, &section_headers,  &keys,
      &signature_info, &signature, control_info);

  num_sections = self_load_sections (in, &self, &elf, &phdr,
      &metadata_header, &section_headers, &keys, &sections);

  fclose (in);

  out = fopen (argv[2], "wb");
  if (out == NULL) {
    ERROR (-2, "Can't open output file");
  }

	if (argc > 3) {
    keypair = fopen(argv[3], "wb");
		fwrite(&metadata_info, 0x40, 1, keypair);
		fclose(keypair);		
  }

  if (argc == 5)
    patch = 1;

  for (i = 0; i < num_sections; i++) {
    if (sections[i].offset == UINT64_MAX) {
        continue;
    }
    fseek (out, sections[i].offset, SEEK_SET);

	if (patch)
		patch_sdk(sections[i].size, sections[i].data);

	if (fwrite (sections[i].data, 1, sections[i].size, out) != sections[i].size) {
      ERROR (-7, "Error writing section");
    }
  }

  self_free_sections (&sections, num_sections);

  return 0;
}
