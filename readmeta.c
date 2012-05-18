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

  if (argc < 3) {
    fprintf(stderr, "usage: %s in.self out.meta\n", argv[0]);
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

  fclose (in);

  out = fopen (argv[2], "wb");
  if (out == NULL) {
    ERROR (-2, "Can't open output file");
  }

  fwrite(&metadata_info, 1, sizeof(metadata_info), out);
  fwrite(&metadata_header, 1, sizeof(metadata_header), out);
  fwrite(&signature_info, 1, sizeof(signature_info), out);
  fwrite(&signature, 1, sizeof(signature), out);
  fwrite(&control_info, 1, sizeof(control_info), out);

  fclose(out);

  return 0;
}
