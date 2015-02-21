#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_whirlpool.h"

#define DEBUG_ALGO

static void whirlpoolx_hash(void *output, const void *input)
{
	unsigned char hash[64];

	memset(hash, 0, sizeof(hash));

	sph_whirlpool_context ctx_whirlpool;

	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool(&ctx_whirlpool, input, 80);
	sph_whirlpool_close(&ctx_whirlpool, hash);

    unsigned char hash_xored[sizeof(hash) / 2];
    
	for (uint32_t i = 0; i < (sizeof(hash) / 2); i++)
	{
        hash_xored[i] =
            hash[i] ^ hash[i + ((sizeof(hash) / 2) / 2)]
        ;
	}
    
	memcpy(output, hash_xored, 32);
}

int scanhash_whirlpoolx(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                    uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];

	int kk=0;
	for (; kk < 32; kk++)
	{
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		whirlpoolx_hash(hash64, &endiandata);
        if (((hash64[7]&0xFFFFFF00)==0) &&
				fulltest(hash64, ptarget)) {
            *hashes_done = n - first_nonce + 1;
			return true;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
    
	*hashes_done = n - first_nonce + 1;
    
	pdata[19] = n;
	return 0;
}
