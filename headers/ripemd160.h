/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _RIPEMD160_H
#define _RIPEMD160_H


#include <SupportDefs.h>


#define RIPEMD160_DIGESTSIZE	20
#define RIPEMD160_BLOCKSIZE		64

/* RMD160 context. */
typedef struct ripemd160_context {
	uint32	state[5];	/* state */
	uint64	count;		/* number of bits, modulo 2^64 */
	uint8	buffer[64];	/* input buffer */
} ripemd160_context;

#ifdef __cplusplus
extern "C" {
#endif

void ripemd160_init(ripemd160_context *context);
void ripemd160_transform(uint32 *state, const uint8 *block);
void ripemd160_update(ripemd160_context *context, const uint8 *input,
	uint32 length);
void ripemd160_final(uint8 *digest, ripemd160_context *context);

#ifdef __cplusplus
}
#endif

#endif	/* _RIPEMD160_H */
