#ifndef siphash_H
#define siphash_H

#define crypto_shorthash_siphash24_BYTES 8U
#define crypto_shorthash_siphash24_KEYBYTES 16U

int crypto_shorthash_siphash24(unsigned char *out,
                               const unsigned char *in,
                               unsigned long long inlen,
                               const unsigned char *k);

#endif
