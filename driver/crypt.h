#ifndef CRYPT_H
#define CRYPT_H


#include "aes.h"
#include "gf_mul.h"


#define PKCS5_SALT_SIZE			64
#define SECONDARY_KEY_SIZE		32
#define KEY_SIZE				(sizeof(aes_encrypt_ctx) + sizeof(aes_decrypt_ctx))

struct crypt_context {
	struct galois_field_context gf_context;
	uint8	key_salt[PKCS5_SALT_SIZE];
	uint8	secondary_key[SECONDARY_KEY_SIZE];
	uint8	key_schedule[KEY_SIZE];
	off_t	offset;
	off_t	size;
	bool	hidden;
};


void derive_key_ripemd160(const uint8 *key, int keyLength, const uint8 *salt,
	int saltLength, int iterations, uint8 *diskKey, int diskKeyLength);

void encrypt_block(crypt_context& context, uint8 *data, uint32 length,
	uint64 blockIndex);
void decrypt_block(crypt_context& context, uint8 *data, int length,
	uint64 blockIndex);
void encrypt_buffer(crypt_context& context, uint8 *buffer, uint32 length);
void decrypt_buffer(crypt_context& context, uint8 *buffer, uint32 length);

status_t detect_drive(crypt_context& context, int fd, const uint8* key,
	uint32 keyLength);
status_t setup_drive(crypt_context& context, int fd, const uint8* key,
	uint32 keyLength, const uint8* random, uint32 randomLength);
status_t init_key(crypt_context& context, uint8* diskKey);
void init_context(crypt_context& context);

#endif	// CRYPT_H
