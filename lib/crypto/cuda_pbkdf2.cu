extern "C"{
#include "cuda_pbkdf2.h"
#include "../utils.h"
}
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <cuda.h>

__device__
void sha1_process( const SHA_DEV_CTX *ctx, SHA_DEV_CTX *data) {

  uint32_t temp, W[80], A, B, C, D, E, i;

  W[ 0] = data->h0;
  W[ 1] = data->h1;
  W[ 2] = data->h2;
  W[ 3] = data->h3;
  W[ 4] = data->h4;
  W[ 5] = 0x80000000;
  W[ 6] = 0;
  W[ 7] = 0;
  W[ 8] = 0;
  W[ 9] = 0;
  W[10] = 0;
  W[11] = 0;
  W[12] = 0;
  W[13] = 0;
  W[14] = 0;
  W[15] = (64+20)*8;

  A = ctx->h0;
  B = ctx->h1;
  C = ctx->h2;
  D = ctx->h3;
  E = ctx->h4;

#undef S
#define S(x,n) ((x << n) | (x >> (32 - n)))

#undef R
#define R(t)                           \
{                                      \
    temp = W[t -  3] ^ W[t -  8] ^     \
           W[t - 14] ^ W[t - 16];      \
           W[t] = S(temp,1);           \
}

#undef P
#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

  for(i=16;i<80;i++)
	  R(i);
  
  
  P( A, B, C, D, E, W[0]  );
  P( E, A, B, C, D, W[1]  );
  P( D, E, A, B, C, W[2]  );
  P( C, D, E, A, B, W[3]  );
  P( B, C, D, E, A, W[4]  );
  P( A, B, C, D, E, W[5]  );
  P( E, A, B, C, D, W[6]  );
  P( D, E, A, B, C, W[7]  );
  P( C, D, E, A, B, W[8]  );
  P( B, C, D, E, A, W[9]  );
  P( A, B, C, D, E, W[10] );
  P( E, A, B, C, D, W[11] );
  P( D, E, A, B, C, W[12] );
  P( C, D, E, A, B, W[13] );
  P( B, C, D, E, A, W[14] );
  P( A, B, C, D, E, W[15] );
  P( E, A, B, C, D, W[16] );
  P( D, E, A, B, C, W[17] );
  P( C, D, E, A, B, W[18] );
  P( B, C, D, E, A, W[19] );
  
#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
  
  P( A, B, C, D, E, W[20] );
  P( E, A, B, C, D, W[21] );
  P( D, E, A, B, C, W[22] );
  P( C, D, E, A, B, W[23] );
  P( B, C, D, E, A, W[24] );
  P( A, B, C, D, E, W[25] );
  P( E, A, B, C, D, W[26] );
  P( D, E, A, B, C, W[27] );
  P( C, D, E, A, B, W[28] );
  P( B, C, D, E, A, W[29] );
  P( A, B, C, D, E, W[30] );
  P( E, A, B, C, D, W[31] );
  P( D, E, A, B, C, W[32] );
  P( C, D, E, A, B, W[33] );
  P( B, C, D, E, A, W[34] );
  P( A, B, C, D, E, W[35] );
  P( E, A, B, C, D, W[36] );
  P( D, E, A, B, C, W[37] );
  P( C, D, E, A, B, W[38] );
  P( B, C, D, E, A, W[39] );
  
#undef K
#undef F
  
#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
  
  P( A, B, C, D, E, W[40] );
  P( E, A, B, C, D, W[41] );
  P( D, E, A, B, C, W[42] );
  P( C, D, E, A, B, W[43] );
  P( B, C, D, E, A, W[44] );
  P( A, B, C, D, E, W[45] );
  P( E, A, B, C, D, W[46] );
  P( D, E, A, B, C, W[47] );
  P( C, D, E, A, B, W[48] );
  P( B, C, D, E, A, W[49] );
  P( A, B, C, D, E, W[50] );
  P( E, A, B, C, D, W[51] );
  P( D, E, A, B, C, W[52] );
  P( C, D, E, A, B, W[53] );
  P( B, C, D, E, A, W[54] );
  P( A, B, C, D, E, W[55] );
  P( E, A, B, C, D, W[56] );
  P( D, E, A, B, C, W[57] );
  P( C, D, E, A, B, W[58] );
  P( B, C, D, E, A, W[59] );
  
#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
  
  P( A, B, C, D, E, W[60] );
  P( E, A, B, C, D, W[61] );
  P( D, E, A, B, C, W[62] );
  P( C, D, E, A, B, W[63] );
  P( B, C, D, E, A, W[64] );
  P( A, B, C, D, E, W[65] );
  P( E, A, B, C, D, W[66] );
  P( D, E, A, B, C, W[67] );
  P( C, D, E, A, B, W[68] );
  P( B, C, D, E, A, W[69] );
  P( A, B, C, D, E, W[70] );
  P( E, A, B, C, D, W[71] );
  P( D, E, A, B, C, W[72] );
  P( C, D, E, A, B, W[73] );
  P( B, C, D, E, A, W[74] );
  P( A, B, C, D, E, W[75] );
  P( E, A, B, C, D, W[76] );
  P( D, E, A, B, C, W[77] );
  P( C, D, E, A, B, W[78] );
  P( B, C, D, E, A, W[79] );
  
#undef K
#undef F

  data->h0 = ctx->h0 + A;
  data->h1 = ctx->h1 + B;
  data->h2 = ctx->h2 + C;
  data->h3 = ctx->h3 + D;
  data->h4 = ctx->h4 + E;

}

__global__ void kernel_pbkdf2_sha1_32( gpu_inbuffer *inbuffer, 
									gpu_outbuffer *outbuffer, int iterations) {
    int i;
	SHA_DEV_CTX temp_ctx, pmk_ctx;
    
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;  
    
    CPY_DEVCTX(inbuffer[idx].e1, temp_ctx);
    CPY_DEVCTX(temp_ctx, pmk_ctx);

    for( i = 0; i < iterations-1; i++ ){
        sha1_process( &inbuffer[idx].ctx_ipad, &temp_ctx);
        sha1_process( &inbuffer[idx].ctx_opad, &temp_ctx);
        pmk_ctx.h0 ^= temp_ctx.h0; pmk_ctx.h1 ^= temp_ctx.h1;
        pmk_ctx.h2 ^= temp_ctx.h2; pmk_ctx.h3 ^= temp_ctx.h3;
        pmk_ctx.h4 ^= temp_ctx.h4;
    }

    CPY_DEVCTX(pmk_ctx, outbuffer[idx].pmk1);
    CPY_DEVCTX(inbuffer[idx].e2, temp_ctx);
    CPY_DEVCTX(temp_ctx, pmk_ctx);

    for( i = 0; i < iterations-1; i++ ){
        sha1_process( &inbuffer[idx].ctx_ipad, &temp_ctx);
        sha1_process( &inbuffer[idx].ctx_opad, &temp_ctx);
        pmk_ctx.h0 ^= temp_ctx.h0; pmk_ctx.h1 ^= temp_ctx.h1;
        pmk_ctx.h2 ^= temp_ctx.h2; pmk_ctx.h3 ^= temp_ctx.h3;
        pmk_ctx.h4 ^= temp_ctx.h4;
    }

    CPY_DEVCTX(pmk_ctx, outbuffer[idx].pmk2);
}


/* Custom version of pbkdf2: 
 * - Works on a list of passwords 
 * - Outputs a list of 32byte derived keys
 * - num_pwds must be multiple of 64
 */
int cuda_pbkdf2_hmac_sha1_32(unsigned char **pwdlst, int num_pwds, unsigned char *salt, 
						  size_t saltlen, uint32_t iterations, uint8_t **key){


	unsigned char pad[64], temp[32], *passwd;
	int i=0,j=0,passwdlen;
	SHA_CTX ctx_pad;
    gpu_inbuffer *h_inbuffer, *d_inbuffer;
    gpu_outbuffer *h_outbuffer, *d_outbuffer;
	cudaError_t cudaReturnValue;
	
	/* cuda allocation */
	h_inbuffer = (gpu_inbuffer *)calloc(num_pwds, sizeof(gpu_inbuffer));
	if(h_inbuffer == NULL){
		errprint("Malloc error\n");
		return 0;
	}

	h_outbuffer = (gpu_outbuffer *)calloc(num_pwds, sizeof(gpu_outbuffer));
	if(h_outbuffer == NULL){
		errprint("Malloc error\n");
		return 0;
	}

	cudaReturnValue = cudaMalloc((void **) &d_inbuffer, (num_pwds) * sizeof(gpu_inbuffer));
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	cudaReturnValue = cudaMalloc((void **) &d_outbuffer, (num_pwds) * sizeof(gpu_outbuffer));
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	for(i = 0; i < num_pwds; i++){
		passwd = pwdlst[i];
		passwdlen = strlen((const char *)passwd);

		memcpy(pad, passwd, passwdlen);
        memset(pad + passwdlen, 0, sizeof(pad) - passwdlen);

        for (j = 0; j < 16; j++)
            ((unsigned int*)pad)[j] ^= 0x36363636;

        SHA1_Init(&ctx_pad);
        SHA1_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX(ctx_pad, h_inbuffer[i].ctx_ipad);

        for (j = 0; j < 16; j++)
            ((unsigned int*)pad)[j] ^= 0x6a6a6a6a;

        SHA1_Init(&ctx_pad);
        SHA1_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX(ctx_pad, h_inbuffer[i].ctx_opad);

        salt[saltlen + 4 - 1] = '\1';
        HMAC(EVP_sha1(), passwd, passwdlen, salt, saltlen + 4, temp, NULL);
        GET_BE(h_inbuffer[i].e1.h0, temp, 0);
        GET_BE(h_inbuffer[i].e1.h1, temp, 4);
        GET_BE(h_inbuffer[i].e1.h2, temp, 8);
        GET_BE(h_inbuffer[i].e1.h3, temp, 12);
        GET_BE(h_inbuffer[i].e1.h4, temp, 16);

        salt[saltlen + 4 - 1] = '\2';
        HMAC(EVP_sha1(), passwd, passwdlen, salt, saltlen + 4, temp, NULL);
        GET_BE(h_inbuffer[i].e2.h0, temp, 0);
        GET_BE(h_inbuffer[i].e2.h1, temp, 4);
        GET_BE(h_inbuffer[i].e2.h2, temp, 8);
        GET_BE(h_inbuffer[i].e2.h3, temp, 12);
        GET_BE(h_inbuffer[i].e2.h4, temp, 16);
	}

	cudaReturnValue = cudaMemcpy(d_inbuffer, h_inbuffer, num_pwds * sizeof(gpu_inbuffer), cudaMemcpyHostToDevice);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}


	/* call the cuda kernel */
	kernel_pbkdf2_sha1_32<<<num_pwds/64, 64>>>(d_inbuffer, d_outbuffer, iterations);
	cudaDeviceSynchronize();

	if((cudaReturnValue = cudaGetLastError()) != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
        return 0;
    }

	cudaReturnValue = cudaMemcpy(h_outbuffer, d_outbuffer, num_pwds * sizeof(gpu_outbuffer), cudaMemcpyDeviceToHost);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}
	
	for(i=0;i<num_pwds;i++){
	    PUT_BE(h_outbuffer[0].pmk1.h0, temp,  0); PUT_BE(h_outbuffer[0].pmk1.h1, temp,  4);
	    PUT_BE(h_outbuffer[0].pmk1.h2, temp,  8); PUT_BE(h_outbuffer[0].pmk1.h3, temp, 12);
	    PUT_BE(h_outbuffer[0].pmk1.h4, temp, 16); PUT_BE(h_outbuffer[0].pmk2.h0, temp, 20);
	    PUT_BE(h_outbuffer[0].pmk2.h1, temp, 24); PUT_BE(h_outbuffer[0].pmk2.h2, temp, 28);
		memcpy(key[i], temp, 32);
	}

	cudaReturnValue = cudaFree(d_inbuffer);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	cudaReturnValue = cudaFree(d_outbuffer);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	free(h_outbuffer);
	free(h_inbuffer);

	return 1;

}
