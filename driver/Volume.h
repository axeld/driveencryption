/*
 * Copyright 2008-2025, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */
#ifndef VOLUME_H
#define VOLUME_H


#include <SupportDefs.h>


class CryptContext;

struct true_crypt_header;


class Volume {
public:
	Volume(CryptContext& context);
	~Volume();

	status_t Detect(int fd, const uint8* key, uint32 keyLength);
	status_t Setup(int fd, const uint8* key, uint32 keyLength,
		const uint8* random, uint32 randomLength);
	status_t SetPassword(int fd, const uint8* oldKey, uint32 oldKeyLength,
		const uint8* newKey, uint32 newKeyLength);
	status_t Resize(int fd, const uint8* key, uint32 keyLength, off_t newSize);

	off_t Offset() const { return fOffset; }
	off_t Size() const { return fSize; }
	bool IsHidden() const { return fHidden; }

protected:
	status_t _Detect(int fd, const uint8* key, uint32 keyLength, off_t& offset,
		uint8* buffer, true_crypt_header& header);
	status_t _Detect(int fd, off_t offset, off_t size, const uint8* key,
		uint32 keyLength, uint8* buffer, true_crypt_header& header);
	status_t _WriteHeader(int fd, const uint8* key, uint32 keyLength,
		off_t headerOffset, uint8* buffer);

private:
	CryptContext&			fContext;
	off_t					fOffset;
	off_t					fSize;
	bool					fHidden;
};


#endif	// VOLUME_H
