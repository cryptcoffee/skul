extern "C"{
#include "../utils.h"
#include "cuda_pbkdf2.h"
}
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <cuda.h>

__device__
void sha256_process( const SHA256_DEV_CTX *ctx, SHA256_DEV_CTX *data){

	uint32_t temp1, temp2, W[64], A, B, C, D, E, F, G, H, i;

	W[ 0] = data->h0;
	W[ 1] = data->h1;
	W[ 2] = data->h2;
	W[ 3] = data->h3;
	W[ 4] = data->h4;
	W[ 5] = data->h5;
	W[ 6] = data->h6;
	W[ 7] = data->h7;
	W[ 8] = 0x80000000;
	W[ 9] = 0;
	W[10] = 0;
	W[11] = 0;
	W[12] = 0;
	W[13] = 0;
	W[14] = 0;
	W[15] = (64+32)*8;

	A = ctx->h0;
	B = ctx->h1;
	C = ctx->h2;
	D = ctx->h3;
	E = ctx->h4;
	F = ctx->h5;
	G = ctx->h6;
	H = ctx->h7;

#undef RS
#define RS(x,n) (x >> n)

#undef RR
#define RR(x,n) ((x >> n) | (x << (32 - n)))

#undef R
#define R(t)																	\
(																				\
	temp1 = RR( W[(t - 15)],  7) ^ RR( W[(t - 15)], 18) ^			\
			RS( W[(t - 15)],  3),										\
	temp2 = RR( W[(t -  2)], 17) ^ RR( W[(t -  2)], 19) ^			\
			RS( W[(t -  2)], 10),										\
	( W[t] = W[(t - 16)] + temp1 + W[(t -  7)] + temp2 )	\
)

#undef S1
#define S1(x) (RR(x,6) ^ RR(x,11) ^ RR(x,25))

#undef S0
#define S0(x) (RR(x,2) ^ RR(x,13) ^ RR(x,22))

#undef maj
#define maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

#undef ch
#define ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))

#undef P
#define P(a,b,c,d,e,f,g,h,x,K)					\
{												\
	temp1 = h + S1(e) + ch(e,f,g) + K + x;		\
	temp2 = S0(a) + maj(a,b,c);					\
	d += temp1;									\
	h = temp1 + temp2;							\
}

	for(i=16;i<64;i++){
		R(i);
	}

	P( A, B, C, D, E, F, G, H, W[ 0], 0x428a2f98 );
	P( H, A, B, C, D, E, F, G, W[ 1], 0x71374491 );
	P( G, H, A, B, C, D, E, F, W[ 2], 0xb5c0fbcf );
	P( F, G, H, A, B, C, D, E, W[ 3], 0xe9b5dba5 );
	P( E, F, G, H, A, B, C, D, W[ 4], 0x3956c25b );
	P( D, E, F, G, H, A, B, C, W[ 5], 0x59f111f1 );
	P( C, D, E, F, G, H, A, B, W[ 6], 0x923f82a4 );
	P( B, C, D, E, F, G, H, A, W[ 7], 0xab1c5ed5 );
	P( A, B, C, D, E, F, G, H, W[ 8], 0xd807aa98 );
	P( H, A, B, C, D, E, F, G, W[ 9], 0x12835b01 );
	P( G, H, A, B, C, D, E, F, W[10], 0x243185be );
	P( F, G, H, A, B, C, D, E, W[11], 0x550c7dc3 );
	P( E, F, G, H, A, B, C, D, W[12], 0x72be5d74 );
	P( D, E, F, G, H, A, B, C, W[13], 0x80deb1fe );
	P( C, D, E, F, G, H, A, B, W[14], 0x9bdc06a7 );
	P( B, C, D, E, F, G, H, A, W[15], 0xc19bf174 );
	P( A, B, C, D, E, F, G, H, W[16], 0xe49b69c1 );
	P( H, A, B, C, D, E, F, G, W[17], 0xefbe4786 );
	P( G, H, A, B, C, D, E, F, W[18], 0x0fc19dc6 );
	P( F, G, H, A, B, C, D, E, W[19], 0x240ca1cc );
	P( E, F, G, H, A, B, C, D, W[20], 0x2de92c6f );
	P( D, E, F, G, H, A, B, C, W[21], 0x4a7484aa );
	P( C, D, E, F, G, H, A, B, W[22], 0x5cb0a9dc );
	P( B, C, D, E, F, G, H, A, W[23], 0x76f988da );
	P( A, B, C, D, E, F, G, H, W[24], 0x983e5152 );
	P( H, A, B, C, D, E, F, G, W[25], 0xa831c66d );
	P( G, H, A, B, C, D, E, F, W[26], 0xb00327c8 );
	P( F, G, H, A, B, C, D, E, W[27], 0xbf597fc7 );
	P( E, F, G, H, A, B, C, D, W[28], 0xc6e00bf3 );
	P( D, E, F, G, H, A, B, C, W[29], 0xd5a79147 );
	P( C, D, E, F, G, H, A, B, W[30], 0x06ca6351 );
	P( B, C, D, E, F, G, H, A, W[31], 0x14292967 );
	P( A, B, C, D, E, F, G, H, W[32], 0x27b70a85 );
	P( H, A, B, C, D, E, F, G, W[33], 0x2e1b2138 );
	P( G, H, A, B, C, D, E, F, W[34], 0x4d2c6dfc );
	P( F, G, H, A, B, C, D, E, W[35], 0x53380d13 );
	P( E, F, G, H, A, B, C, D, W[36], 0x650a7354 );
	P( D, E, F, G, H, A, B, C, W[37], 0x766a0abb );
	P( C, D, E, F, G, H, A, B, W[38], 0x81c2c92e );
	P( B, C, D, E, F, G, H, A, W[39], 0x92722c85 );
	P( A, B, C, D, E, F, G, H, W[40], 0xa2bfe8a1 );
	P( H, A, B, C, D, E, F, G, W[41], 0xa81a664b );
	P( G, H, A, B, C, D, E, F, W[42], 0xc24b8b70 );
	P( F, G, H, A, B, C, D, E, W[43], 0xc76c51a3 );
	P( E, F, G, H, A, B, C, D, W[44], 0xd192e819 );
	P( D, E, F, G, H, A, B, C, W[45], 0xd6990624 );
	P( C, D, E, F, G, H, A, B, W[46], 0xf40e3585 );
	P( B, C, D, E, F, G, H, A, W[47], 0x106aa070 );
	P( A, B, C, D, E, F, G, H, W[48], 0x19a4c116 );
	P( H, A, B, C, D, E, F, G, W[49], 0x1e376c08 );
	P( G, H, A, B, C, D, E, F, W[50], 0x2748774c );
	P( F, G, H, A, B, C, D, E, W[51], 0x34b0bcb5 );
	P( E, F, G, H, A, B, C, D, W[52], 0x391c0cb3 );
	P( D, E, F, G, H, A, B, C, W[53], 0x4ed8aa4a );
	P( C, D, E, F, G, H, A, B, W[54], 0x5b9cca4f );
	P( B, C, D, E, F, G, H, A, W[55], 0x682e6ff3 );
	P( A, B, C, D, E, F, G, H, W[56], 0x748f82ee );
	P( H, A, B, C, D, E, F, G, W[57], 0x78a5636f );
	P( G, H, A, B, C, D, E, F, W[58], 0x84c87814 );
	P( F, G, H, A, B, C, D, E, W[59], 0x8cc70208 );
	P( E, F, G, H, A, B, C, D, W[60], 0x90befffa );
	P( D, E, F, G, H, A, B, C, W[61], 0xa4506ceb );
	P( C, D, E, F, G, H, A, B, W[62], 0xbef9a3f7 );
	P( B, C, D, E, F, G, H, A, W[63], 0xc67178f2 );

	data->h0 = ctx->h0 + A;
	data->h1 = ctx->h1 + B;
	data->h2 = ctx->h2 + C;
	data->h3 = ctx->h3 + D;
	data->h4 = ctx->h4 + E;
	data->h5 = ctx->h5 + F;
	data->h6 = ctx->h6 + G;
	data->h7 = ctx->h7 + H;
}

__global__ void kernel_pbkdf2_sha256_32( gpu_inbuffer256 *inbuffer, 
				gpu_outbuffer256 *outbuffer, int *iterations, int num_pwds) {

    int i;
	SHA256_DEV_CTX temp_ctx, pmk_ctx;

    const int idx = blockIdx.x * blockDim.x + threadIdx.x;

	if(idx<num_pwds){
		    CPY_DEVCTX2(inbuffer[idx].e1, temp_ctx);
		    CPY_DEVCTX2(temp_ctx, pmk_ctx);

		    for( i = 0; i < iterations[idx]-1; i++ ){
		    	sha256_process( &inbuffer[idx].ctx_ipad, &temp_ctx);
		    	sha256_process( &inbuffer[idx].ctx_opad, &temp_ctx);
		        pmk_ctx.h0 ^= temp_ctx.h0; pmk_ctx.h1 ^= temp_ctx.h1;
		        pmk_ctx.h2 ^= temp_ctx.h2; pmk_ctx.h3 ^= temp_ctx.h3;
		        pmk_ctx.h4 ^= temp_ctx.h4; pmk_ctx.h5 ^= temp_ctx.h5;
				pmk_ctx.h6 ^= temp_ctx.h6; pmk_ctx.h7 ^= temp_ctx.h7;
		    }
		    CPY_DEVCTX2(pmk_ctx, outbuffer[idx].pmk);
	}
}


extern "C"{
int cuda_pbkdf2_hmac_sha256_32(unsigned char **pwdlst, size_t num_pwds, 
				unsigned char *salt, size_t saltlen, uint32_t iterations, 
				uint8_t **key){


	unsigned char pad[64], temp[32], *passwd;
	int i=0, j=0, passwdlen,r=1, *d_iter, blks;
	SHA256_CTX ctx_pad;
    gpu_inbuffer256 *h_inbuffer, *d_inbuffer;
    gpu_outbuffer256 *h_outbuffer, *d_outbuffer;
	cudaError_t cudaReturnValue;

	h_inbuffer = (gpu_inbuffer256 *)calloc(num_pwds, sizeof(gpu_inbuffer256));
	if(h_inbuffer == NULL){
		errprint("Malloc error\n");
		return 0;
	}

	h_outbuffer = (gpu_outbuffer256 *)calloc(num_pwds, sizeof(gpu_outbuffer256));
	if(h_outbuffer == NULL){
		errprint("Malloc error\n");
		return 0;
	}

	cudaReturnValue = cudaMalloc((void **) &d_iter, (num_pwds) * sizeof(int));
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	cudaReturnValue = cudaMalloc((void **) &d_inbuffer, (num_pwds) * sizeof(gpu_inbuffer256));
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	cudaReturnValue = cudaMalloc((void **) &d_outbuffer, (num_pwds) * sizeof(gpu_outbuffer256));
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	for(i = 0; i < num_pwds; i++){

		cudaReturnValue = cudaMemcpy(&d_iter[i], &iterations, sizeof(int), cudaMemcpyHostToDevice);
		if(cudaReturnValue != cudaSuccess){
			errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));

			r=0;
			goto end;
		}

		passwd = pwdlst[i];
		passwdlen = strlen((const char *)passwd);

		memcpy(pad, passwd, passwdlen);
        memset(pad + passwdlen, 0, sizeof(pad) - passwdlen);

        for (j = 0; j < 16; j++)
            ((unsigned int*)pad)[j] ^= 0x36363636;

        SHA256_Init(&ctx_pad);
        SHA256_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX2_openSSL(ctx_pad, h_inbuffer[i].ctx_ipad);

        for (j = 0; j < 16; j++)
            ((unsigned int*)pad)[j] ^= 0x6a6a6a6a;

        SHA256_Init(&ctx_pad);
        SHA256_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX2_openSSL(ctx_pad, h_inbuffer[i].ctx_opad);

        salt[saltlen + 4 - 1] = '\1';
        HMAC(EVP_sha256(), passwd, passwdlen, salt, saltlen + 4, temp, NULL);
        GET_BE(h_inbuffer[i].e1.h0, temp, 0);
        GET_BE(h_inbuffer[i].e1.h1, temp, 4);
        GET_BE(h_inbuffer[i].e1.h2, temp, 8);
        GET_BE(h_inbuffer[i].e1.h3, temp, 12);
        GET_BE(h_inbuffer[i].e1.h4, temp, 16);
        GET_BE(h_inbuffer[i].e1.h5, temp, 20);
        GET_BE(h_inbuffer[i].e1.h6, temp, 24);
        GET_BE(h_inbuffer[i].e1.h7, temp, 28);

	}

	cudaReturnValue = cudaMemcpy(d_inbuffer, h_inbuffer, num_pwds * sizeof(gpu_inbuffer256), cudaMemcpyHostToDevice);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		r=0;
		goto end;
	}

	blks = ceil((num_pwds/64));

	kernel_pbkdf2_sha256_32<<<blks, 64>>>(d_inbuffer, d_outbuffer, d_iter, num_pwds);
	cudaDeviceSynchronize();

	if((cudaReturnValue = cudaGetLastError()) != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		r=0;
		goto end;
    }

	cudaReturnValue = cudaMemcpy(h_outbuffer, d_outbuffer, num_pwds * sizeof(gpu_outbuffer256), cudaMemcpyDeviceToHost);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		r=0;
		goto end;
	}
	
	for(i=0;i<num_pwds;i++){
	    PUT_BE(h_outbuffer[i].pmk.h0, temp,  0); 
		PUT_BE(h_outbuffer[i].pmk.h1, temp,  4);
		PUT_BE(h_outbuffer[i].pmk.h2, temp,  8); 
		PUT_BE(h_outbuffer[i].pmk.h3, temp, 12);
		PUT_BE(h_outbuffer[i].pmk.h4, temp, 16); 
		PUT_BE(h_outbuffer[i].pmk.h5, temp, 20);
	    PUT_BE(h_outbuffer[i].pmk.h6, temp, 24); 
		PUT_BE(h_outbuffer[i].pmk.h7, temp, 28);
		memcpy(key[i], temp, 32);
	}

end:

	cudaReturnValue = cudaFree(d_inbuffer);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	cudaReturnValue = cudaFree(d_outbuffer);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		r=0;
		return 0;
	}

	free(h_outbuffer);
	free(h_inbuffer);

	return r;

}
}/* end of extern "C"{ */

