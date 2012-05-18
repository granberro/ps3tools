/*
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __GPKG_H__
#define __GPKG_H__

#define PKG_MAGIC 0x7F504B47
#define PKG_RETAIL 0x80000001
#define PKG_DEBUG 0x00000001

typedef struct {
  u32 magic; //pkg magic ("\0x7FPKG")
  u32 type; //pkg type
  u32 info_offset; //pkg info offset
  u32 info_size; //info size / 8
  u32 header_size; //size of block of metadata (block after header)                       
  u32 file_count; //count of contained files
  u64 pkg_size; //pkg size
  u64 offset; //file table offset
  u64 size; //data size (data at 0x100 - 0x80 bytes)
  u8 title_id[48]; //title id
  u8 qa_digest[16]; //the encryption/decryption key for debug pkgs (generated from data hash)
  u8 enc_licence[16]; //encrypted licence with help of qa_digest
  u8 key2[16]; //the encryption/decryption key2 (generated from header hash (bytes 3-12 of hash (00-7f)))
  u8 hash_of_key2[16]; //first 16 bytes of sha1 of key2
  u8 hash_of_key2_1[16]; //first 16 bytes of sha1 of key2 + 1(64b)
  u8 hash_of_key2_2[16]; //first 16 bytes of sha1 of key2 + 2(64b)
} __attribute__((packed)) PKG_HEADER;

struct pkg_file {
	char name[0xFF];
	u8 *ptr;
	u32 name_len;
	u32 name_offset;
	u64 size;
	u64 offset;
	u32 flags;
};

struct id2name_tbl t_file_type[] = {
	{0x01, "SELF"},
	{0x02, "EDAT"},
	{0x03, "RAW"},
	{0x04, "DIR"},
	{0x09, "SDAT"}
};


#endif /* __GPKG_H__ */
