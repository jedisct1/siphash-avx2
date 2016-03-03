
#include <immintrin.h>
#include <stdint.h>
#include <string.h>

#ifndef __GNUC__
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif
#ifndef CRYPTO_ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define CRYPTO_ALIGN(x) __declspec(align(x))
# else
#  define CRYPTO_ALIGN(x) __attribute__ ((aligned(x)))
# endif
#endif

typedef struct SipHashState {
    __m128i v20;
    __m128i v31;
} SipHashState;

static inline __m128i
load_packet_64(const uint8_t *in)
{
    uint64_t packet;

    memcpy(&packet, in, sizeof packet);

    return _mm_cvtsi64_si128(packet);
}

static inline __m128i
load_final_packet_64(const uint8_t* in, const uint64_t size, const unsigned long long offset)
{
    CRYPTO_ALIGN(16) uint8_t buffer[8] = {0};
    memcpy(buffer, in, size - offset);
    buffer[7] = size;
    return load_packet_64(buffer);
}

static inline void
init(SipHashState *state, const uint8_t *k)
{
    const __m128i key = _mm_loadu_si128((const __m128i *) (const void *) k);
    const __m128i init0 =
        key ^ _mm_set_epi64x(0x646f72616e646f6dULL, 0x736f6d6570736575ULL);
    const __m128i init1 =
        key ^ _mm_set_epi64x(0x7465646279746573ULL, 0x6c7967656e657261ULL);

    state->v20 = _mm_unpacklo_epi64(init0, init1);
    state->v31 = _mm_unpackhi_epi64(init0, init1);
}

static inline __m128i
rotate_left(__m128i v31, uint64_t bits3, uint64_t bits1)
{
    const __m128i left = _mm_sllv_epi64(v31, _mm_set_epi64x(bits3, bits1));
    const __m128i right = _mm_srlv_epi64(v31, _mm_set_epi64x(64 - bits3, 64 - bits1));

    return left | right;
}

static inline __m128i
rotate_left_32(__m128i v20)
{
    return _mm_shuffle_epi32(v20, _MM_SHUFFLE(0, 1, 3, 2));
}

static inline void
half_round(SipHashState *state, const uint64_t bits3, const uint64_t bits1)
{
    state->v20 += state->v31;
    state->v31 = rotate_left(state->v31, bits3, bits1);
    state->v31 ^= state->v20;
}

static inline void
compress(SipHashState *state, const int rounds)
{
    int i;

    for (i = 0; i < rounds; i++) {
        half_round(state, 16, 13);
        state->v20 = rotate_left_32(state->v20);
        half_round(state, 21, 17);
        state->v20 = rotate_left_32(state->v20);
    }
}

static inline void
update(SipHashState *state, const __m128i packet)
{
    state->v31 ^= _mm_slli_si128(packet, 8);
    compress(state, 2);
    state->v20 ^= packet;
}

static inline uint64_t
finalize(SipHashState *state)
{
    __m128i v32_10;
    __m128i v32_32;

    state->v20 ^= _mm_set_epi64x(0xFF, 0);
    compress(state, 4);
    v32_10 = state->v20 ^ state->v31;
    v32_32 = _mm_unpackhi_epi64(v32_10, v32_10);

    return _mm_cvtsi128_si64(v32_10 ^ v32_32);
}

int
crypto_shorthash_siphash24(unsigned char *out, const unsigned char *in,
                           unsigned long long inlen, const unsigned char *k)
{
    SipHashState       state;
    __m128i            packet;
    unsigned long long offset;
    uint64_t            h;

    init(&state, k);
    for (offset = 0; offset < (inlen & ~(unsigned long long) 7); offset += 8) {
        packet = load_packet_64(in + offset);
        update(&state, packet);
    }
    packet = load_final_packet_64(in + offset, inlen, offset);
    update(&state, packet);
    h = finalize(&state);
    memcpy(out, &h, sizeof h);

    return 0;
}
