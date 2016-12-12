extern "C"{
#include "../utils.h"
#include "cuda_pbkdf2.h"
}
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <cuda.h>

__device__
void sha512_process( const SHA512_DEV_CTX *ctx, SHA512_DEV_CTX *data){

	uint64_t temp1, temp2, W[16], A, B, C, D, E, F, G, H;

	W[ 0] = data->h0;
	W[ 1] = data->h1;
	W[ 2] = data->h2;
	W[ 3] = data->h3;
	W[ 4] = data->h4;
	W[ 5] = data->h5;
	W[ 6] = data->h6;
	W[ 7] = data->h7;
	W[ 8] = 0x8000000000000000;
	W[ 9] = 0;
	W[10] = 0;
	W[11] = 0;
	W[12] = 0;
	W[13] = 0;
	W[14] = 0;
	W[15] = (128+64)*8;

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
#define RR(x,n) ((x >> n) | (x << (64 - n)))

#undef R
#define R(t)																	\
(																				\
	temp1 = RR( W[(t - 15) & 0x0F],  1) ^ RR( W[(t - 15) & 0x0F], 8) ^			\
			RS( W[(t - 15) & 0x0F],  7),										\
	temp2 = RR( W[(t -  2) & 0x0F], 19) ^ RR( W[(t -  2) & 0x0F], 61) ^			\
			RS( W[(t -  2) & 0x0F], 6),											\
	( W[t & 0x0F] = W[(t - 16) & 0x0F] + temp1 + W[(t -  7) & 0x0F] + temp2 )	\
)

#undef S1
#define S1(x) (RR(x,14) ^ RR(x,18) ^ RR(x,41))

#undef S0
#define S0(x) (RR(x,28) ^ RR(x,34) ^ RR(x,39))

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


	P( A, B, C, D, E, F, G, H, W[0] , 0x428a2f98d728ae22 );
	P( H, A, B, C, D, E, F, G, W[1] , 0x7137449123ef65cd );
	P( G, H, A, B, C, D, E, F, W[2] , 0xb5c0fbcfec4d3b2f );
	P( F, G, H, A, B, C, D, E, W[3] , 0xe9b5dba58189dbbc );
	P( E, F, G, H, A, B, C, D, W[4] , 0x3956c25bf348b538 );
	P( D, E, F, G, H, A, B, C, W[5] , 0x59f111f1b605d019 );
	P( C, D, E, F, G, H, A, B, W[6] , 0x923f82a4af194f9b );
	P( B, C, D, E, F, G, H, A, W[7] , 0xab1c5ed5da6d8118 );
	P( A, B, C, D, E, F, G, H, W[8] , 0xd807aa98a3030242 );
	P( H, A, B, C, D, E, F, G, W[9] , 0x12835b0145706fbe );
	P( G, H, A, B, C, D, E, F, W[10], 0x243185be4ee4b28c );
	P( F, G, H, A, B, C, D, E, W[11], 0x550c7dc3d5ffb4e2 );
	P( E, F, G, H, A, B, C, D, W[12], 0x72be5d74f27b896f );
	P( D, E, F, G, H, A, B, C, W[13], 0x80deb1fe3b1696b1 );
	P( C, D, E, F, G, H, A, B, W[14], 0x9bdc06a725c71235 );
	P( B, C, D, E, F, G, H, A, W[15], 0xc19bf174cf692694 );
	P( A, B, C, D, E, F, G, H, R(16), 0xe49b69c19ef14ad2 );
	P( H, A, B, C, D, E, F, G, R(17), 0xefbe4786384f25e3 );
	P( G, H, A, B, C, D, E, F, R(18), 0x0fc19dc68b8cd5b5 );
	P( F, G, H, A, B, C, D, E, R(19), 0x240ca1cc77ac9c65 );
	P( E, F, G, H, A, B, C, D, R(20), 0x2de92c6f592b0275 );
	P( D, E, F, G, H, A, B, C, R(21), 0x4a7484aa6ea6e483 );
	P( C, D, E, F, G, H, A, B, R(22), 0x5cb0a9dcbd41fbd4 );
	P( B, C, D, E, F, G, H, A, R(23), 0x76f988da831153b5 );
	P( A, B, C, D, E, F, G, H, R(24), 0x983e5152ee66dfab );
	P( H, A, B, C, D, E, F, G, R(25), 0xa831c66d2db43210 );
	P( G, H, A, B, C, D, E, F, R(26), 0xb00327c898fb213f );
	P( F, G, H, A, B, C, D, E, R(27), 0xbf597fc7beef0ee4 );
	P( E, F, G, H, A, B, C, D, R(28), 0xc6e00bf33da88fc2 );
	P( D, E, F, G, H, A, B, C, R(29), 0xd5a79147930aa725 );
	P( C, D, E, F, G, H, A, B, R(30), 0x06ca6351e003826f );
	P( B, C, D, E, F, G, H, A, R(31), 0x142929670a0e6e70 );
	P( A, B, C, D, E, F, G, H, R(32), 0x27b70a8546d22ffc );
	P( H, A, B, C, D, E, F, G, R(33), 0x2e1b21385c26c926 );
	P( G, H, A, B, C, D, E, F, R(34), 0x4d2c6dfc5ac42aed );
	P( F, G, H, A, B, C, D, E, R(35), 0x53380d139d95b3df );
	P( E, F, G, H, A, B, C, D, R(36), 0x650a73548baf63de );
	P( D, E, F, G, H, A, B, C, R(37), 0x766a0abb3c77b2a8 );
	P( C, D, E, F, G, H, A, B, R(38), 0x81c2c92e47edaee6 );
	P( B, C, D, E, F, G, H, A, R(39), 0x92722c851482353b );
	P( A, B, C, D, E, F, G, H, R(40), 0xa2bfe8a14cf10364 );
	P( H, A, B, C, D, E, F, G, R(41), 0xa81a664bbc423001 );
	P( G, H, A, B, C, D, E, F, R(42), 0xc24b8b70d0f89791 );
	P( F, G, H, A, B, C, D, E, R(43), 0xc76c51a30654be30 );
	P( E, F, G, H, A, B, C, D, R(44), 0xd192e819d6ef5218 );
	P( D, E, F, G, H, A, B, C, R(45), 0xd69906245565a910 );
	P( C, D, E, F, G, H, A, B, R(46), 0xf40e35855771202a );
	P( B, C, D, E, F, G, H, A, R(47), 0x106aa07032bbd1b8 );
	P( A, B, C, D, E, F, G, H, R(48), 0x19a4c116b8d2d0c8 );
	P( H, A, B, C, D, E, F, G, R(49), 0x1e376c085141ab53 );
	P( G, H, A, B, C, D, E, F, R(50), 0x2748774cdf8eeb99 );
	P( F, G, H, A, B, C, D, E, R(51), 0x34b0bcb5e19b48a8 );
	P( E, F, G, H, A, B, C, D, R(52), 0x391c0cb3c5c95a63 );
	P( D, E, F, G, H, A, B, C, R(53), 0x4ed8aa4ae3418acb );
	P( C, D, E, F, G, H, A, B, R(54), 0x5b9cca4f7763e373 );
	P( B, C, D, E, F, G, H, A, R(55), 0x682e6ff3d6b2b8a3 );
	P( A, B, C, D, E, F, G, H, R(56), 0x748f82ee5defb2fc );
	P( H, A, B, C, D, E, F, G, R(57), 0x78a5636f43172f60 );
	P( G, H, A, B, C, D, E, F, R(58), 0x84c87814a1f0ab72 );
	P( F, G, H, A, B, C, D, E, R(59), 0x8cc702081a6439ec );
	P( E, F, G, H, A, B, C, D, R(60), 0x90befffa23631e28 );
	P( D, E, F, G, H, A, B, C, R(61), 0xa4506cebde82bde9 );
	P( C, D, E, F, G, H, A, B, R(62), 0xbef9a3f7b2c67915 );
	P( B, C, D, E, F, G, H, A, R(63), 0xc67178f2e372532b );
    P( A, B, C, D, E, F, G, H, R(64), 0xca273eceea26619c );
    P( H, A, B, C, D, E, F, G, R(65), 0xd186b8c721c0c207 ); 
    P( G, H, A, B, C, D, E, F, R(66), 0xeada7dd6cde0eb1e );
    P( F, G, H, A, B, C, D, E, R(67), 0xf57d4f7fee6ed178 );
    P( E, F, G, H, A, B, C, D, R(68), 0x06f067aa72176fba );
    P( D, E, F, G, H, A, B, C, R(69), 0x0a637dc5a2c898a6 );
    P( C, D, E, F, G, H, A, B, R(70), 0x113f9804bef90dae );
    P( B, C, D, E, F, G, H, A, R(71), 0x1b710b35131c471b );
	P( A, B, C, D, E, F, G, H, R(72), 0x28db77f523047d84 );
    P( H, A, B, C, D, E, F, G, R(73), 0x32caab7b40c72493 );
    P( G, H, A, B, C, D, E, F, R(74), 0x3c9ebe0a15c9bebc );
    P( F, G, H, A, B, C, D, E, R(75), 0x431d67c49c100d4c );
    P( E, F, G, H, A, B, C, D, R(76), 0x4cc5d4becb3e42b6 );
    P( D, E, F, G, H, A, B, C, R(77), 0x597f299cfc657e2a );
    P( C, D, E, F, G, H, A, B, R(78), 0x5fcb6fab3ad6faec );
    P( B, C, D, E, F, G, H, A, R(79), 0x6c44198c4a475817 );
                                    
                                    
	data->h0 = ctx->h0 + A;
	data->h1 = ctx->h1 + B;
	data->h2 = ctx->h2 + C;
	data->h3 = ctx->h3 + D;
	data->h4 = ctx->h4 + E;
	data->h5 = ctx->h5 + F;
	data->h6 = ctx->h6 + G;
	data->h7 = ctx->h7 + H;

}


__global__ void kernel_pbkdf2_sha512_32( gpu_inbuffer512 *inbuffer, 
									gpu_outbuffer512 *outbuffer, int *iterations, int num_pwds) {
	
	int i;
	SHA512_DEV_CTX temp_ctx, pmk_ctx; 
    
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;  
	if(idx<num_pwds){

	    CPY_DEVCTX2(inbuffer[idx].e1, temp_ctx);
	    CPY_DEVCTX2(temp_ctx, pmk_ctx);
	
	    for( i = 0; i < iterations[idx]-1; i++ ){
	        sha512_process( &inbuffer[idx].ctx_ipad, &temp_ctx);
	        sha512_process( &inbuffer[idx].ctx_opad, &temp_ctx);
	        pmk_ctx.h0 ^= temp_ctx.h0; pmk_ctx.h1 ^= temp_ctx.h1;
	        pmk_ctx.h2 ^= temp_ctx.h2; pmk_ctx.h3 ^= temp_ctx.h3;
	        pmk_ctx.h4 ^= temp_ctx.h4; pmk_ctx.h5 ^= temp_ctx.h5;
			pmk_ctx.h6 ^= temp_ctx.h6; pmk_ctx.h7 ^= temp_ctx.h7;
	    }
	    CPY_DEVCTX2(pmk_ctx, outbuffer[idx].pmk);
	}
}


/* Custom version of pbkdf2_hmac_sha512: 
 * - Works on a list of passwords 
 * - Outputs a list of 32byte derived keys
 */
extern "C"{
int cuda_pbkdf2_hmac_sha512_32(unsigned char **pwdlst, size_t num_pwds, unsigned char *salt, 
						  size_t saltlen, uint32_t iterations, uint8_t **key){


	unsigned char pad[128], temp[64], *passwd;
	size_t i=0;
	int j=0, passwdlen,r=1, *d_iter, blks;
	SHA512_CTX ctx_pad;
    gpu_inbuffer512 *h_inbuffer, *d_inbuffer;
    gpu_outbuffer512 *h_outbuffer, *d_outbuffer;
	cudaError_t cudaReturnValue;

	/* cuda allocation */
	h_inbuffer = (gpu_inbuffer512 *)calloc(num_pwds, sizeof(gpu_inbuffer512));
	if(h_inbuffer == NULL){
		errprint("Malloc error\n");
		return 0;
	}

	h_outbuffer = (gpu_outbuffer512 *)calloc(num_pwds, sizeof(gpu_outbuffer512));
	if(h_outbuffer == NULL){
		errprint("Malloc error\n");
		return 0;
	}

	cudaReturnValue = cudaMalloc((void **) &d_iter, (num_pwds) * sizeof(int));
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	cudaReturnValue = cudaMalloc((void **) &d_inbuffer, (num_pwds) * sizeof(gpu_inbuffer512));
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		return 0;
	}

	cudaReturnValue = cudaMalloc((void **) &d_outbuffer, (num_pwds) * sizeof(gpu_outbuffer512));
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

        for (j = 0; j < 32; j++)
            ((unsigned int*)pad)[j] ^= 0x36363636;
        SHA512_Init(&ctx_pad);
        SHA512_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX2_openSSL(ctx_pad, h_inbuffer[i].ctx_ipad);

        for (j = 0; j < 32; j++)
            ((unsigned int*)pad)[j] ^= 0x6a6a6a6a;
        SHA512_Init(&ctx_pad);
        SHA512_Update(&ctx_pad, pad, sizeof(pad));
        CPY_DEVCTX2_openSSL(ctx_pad, h_inbuffer[i].ctx_opad);

        salt[saltlen + 4 - 1] = '\1';
        HMAC(EVP_sha512(), passwd, passwdlen, salt, saltlen + 4, temp, NULL);
        GET_BE64(h_inbuffer[i].e1.h0, temp, 0);
        GET_BE64(h_inbuffer[i].e1.h1, temp, 8);
        GET_BE64(h_inbuffer[i].e1.h2, temp, 16);
        GET_BE64(h_inbuffer[i].e1.h3, temp, 24);
        GET_BE64(h_inbuffer[i].e1.h4, temp, 32);
        GET_BE64(h_inbuffer[i].e1.h5, temp, 40);
        GET_BE64(h_inbuffer[i].e1.h6, temp, 48);
        GET_BE64(h_inbuffer[i].e1.h7, temp, 56);
	}

	cudaReturnValue = cudaMemcpy(d_inbuffer, h_inbuffer, num_pwds * sizeof(gpu_inbuffer512), cudaMemcpyHostToDevice);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		r=0;
		goto end;
	}

	blks = ceil((num_pwds/64));

	kernel_pbkdf2_sha512_32<<<blks, 64>>>(d_inbuffer, d_outbuffer, d_iter, num_pwds);
	cudaDeviceSynchronize();

	if((cudaReturnValue = cudaGetLastError()) != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		r=0;
		goto end;
    }

	cudaReturnValue = cudaMemcpy(h_outbuffer, d_outbuffer, num_pwds * sizeof(gpu_outbuffer512), cudaMemcpyDeviceToHost);
	if(cudaReturnValue != cudaSuccess){
		errprint("Cuda error: %d - %s\n",cudaReturnValue, cudaGetErrorString(cudaReturnValue));
		r=0;
		goto end;
	}
	
	for(i=0;i<num_pwds;i++){
	    PUT_BE64(h_outbuffer[i].pmk.h0, temp,  0);  PUT_BE64(h_outbuffer[i].pmk.h1, temp,  8);
	    PUT_BE64(h_outbuffer[i].pmk.h2, temp,  16); PUT_BE64(h_outbuffer[i].pmk.h3, temp, 24);
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
