// 50BTCKeyMaker.cpp
//

#include "50BTCKeyMaker.h"

#define RELEASE "0.01"

using namespace std;


bool GetPrivKey(EC_KEY *pkey) {
	// Make New Key
	int res0 = EC_KEY_generate_key(pkey);
	if (res0 != 1) {
		::printf("GetPrivKey() : EC_KEY_generate_key failed \n");
		return false;
	}
	// Get Priv Key
	int nSize = i2d_ECPrivateKey(pkey, NULL);
    //::printf("nSize: %d\n", nSize);// check size
	if (!nSize) {
		::printf("GetPrivKey() : i2d_ECPrivateKey failed \n");
		return false;
	}
	unsigned char vchPrivKey[PRIVATE_KEY_SIZE];
	unsigned char* pbegin = &vchPrivKey[0];
	int kSize = i2d_ECPrivateKey(pkey, &pbegin);
	if (kSize != nSize) {
		::printf("GetPrivKey() : i2d_ECPrivateKey returned unexpected size: %d \n", kSize);
		return false;
	}
	return true;
}


static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int b58enc(unsigned char *b58, size_t *b58sz, unsigned char *src, size_t binsz)
{
	const uint8_t *bin = src;
	int carry;
	size_t i, j, high, zcount = 0;
	size_t size;

	// Find out the length 
	while (zcount < binsz && !bin[zcount])
		++zcount;

	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[64];//uint8_t buf[size];
	memset(buf, 0, 64);//memset(buf, 0, size);

	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
			if (!j)
			{
				break;
			}
		}
	}

	for (j = 0; j < size && !buf[j]; ++j);

	if (*b58sz <= zcount + size - j)
	{
		*b58sz = zcount + size - j + 1;
		return -1;
	}

	if (zcount)
		memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j)
	{
		b58[i] = b58digits_ordered[buf[j]];
	}
	b58[i] = '\0';
	*b58sz = i + 1;

	return 0;
}


int Sha256Hash160(unsigned char *dst, const unsigned char *src, size_t len)
{
	unsigned char hash1[32];
	SHA256(src, len, hash1);
	RIPEMD160(hash1, sizeof(hash1), dst);

	return 0;
}

// Convert Public key Compressed or Uncompressed to BTC address 
int Pub2B58Addr(unsigned char *dstb58, const unsigned char *pbegin, unsigned int nSize)
{
	// Step 1: Hash160 
	unsigned char dst[1 + 20 + 4];
	// Hash 160 
	Sha256Hash160(&dst[1], pbegin, nSize);

	// Step 2: Add BTC Version 
	dst[0] = 0;	// BTC MainNet is 0. TestNet is 111.

	// Step 3: Encode Base58 with Check 
	// Add 4-bytes hash check to the end 

	// 2x SHA256 
	unsigned char *ptr = &dst[0];
	unsigned char hash1[32];
	unsigned char hash2[32];
	SHA256(ptr, 1 + 20, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	memcpy(&ptr[1 + 20], hash2, 4);	// Add 4 last bytes as Checksum

	// Encode Base58 with Check 
	size_t b58sz = 35;
	b58enc(dstb58, &b58sz, dst, sizeof(dst));
	
	return 0;
}


/*
 * Print BTC public Address:
 * An uncompressed public key starts with 04.
 * 
 * - UNCOMPRESSED (bc 0.3.24)
 * - COMPRESSED (bc 0.6+)
 *
 * - P2PKH Pay to Public Key Hash
 * - P2SH  Pay to Script Hash (since 2012-03-15, v0.6.0rc2)
 */
int CreateAddress(EC_KEY *eckey, unsigned char *b58upkh, unsigned char *b58cpkh, unsigned char *b58cpsh)
{
	unsigned char vchPubKey[PUBLIC_KEY_SIZE];
	unsigned char *pbegin = NULL;
	int nSize;
	int kSize;
	
	nSize = i2o_ECPublicKey(eckey, NULL);
	
	if (nSize != sizeof(vchPubKey)) {
		::printf("CreateAddress() : i2o_ECPublicKey() Bad nSize: %d\n", nSize);
		return 0;
	}
	
	kSize = i2o_ECPublicKey(eckey, &pbegin);
	
	if (kSize != sizeof(vchPubKey)) {
		::printf("CreateAddress() : i2o_ECPublicKey() Bad kSize: %d\n", kSize);
		return 0;
	}
	
	// Create P2PKH
	Pub2B58Addr(b58upkh, pbegin, nSize);
	//::printf("P2PKH UAddress: %s\n", b58upkh);
	
	// Convert into compressed public key
	if (pbegin[64] & 1)
		pbegin[0] = 0x03;
	else
		pbegin[0] = 0x02;
	nSize = 33;
	
	Pub2B58Addr(b58cpkh, pbegin, nSize);
	//::printf("P2PKH CAddress: %s\n", b58cpkh);
	
	// Create P2SH
	unsigned char dst[2 + 20];
	Sha256Hash160(&dst[2], pbegin, nSize);
	
	dst[0] = 0x00;
	dst[1] = 0x14;
	unsigned char cdst[1 + 20 + 4];
	Sha256Hash160(&cdst[1], dst, sizeof (dst));
	cdst[0] = 0x05;	// P2SH header
	
	// Append checksum before encoding
	unsigned char hash1[32];
	unsigned char hash2[32];
	SHA256(cdst, 1 + 20, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	memcpy(&cdst[1 + 20], hash2, 4);// Add 4 last bytes as Checksum
	
	size_t b58sz = 35;
	
	b58enc(b58cpsh, &b58sz, cdst, sizeof (cdst));
	//::printf("P2SH  CAddress: %s\n", b58cpsh);
	
	return 1;
}


void PrintAddress(EC_KEY *myecc, unsigned char *b58upkh, unsigned char *b58cpkh, unsigned char *b58cpsh, 
					unsigned char *msg1, unsigned char *msg2) 
{
	const BIGNUM *privKey = NULL;
	char *priv_key_hex = NULL;
	privKey = (BIGNUM *)EC_KEY_get0_private_key(myecc);
	priv_key_hex = BN_bn2hex(privKey);
	
	//::printf("ECCKEY: %s\n", priv_key_hex);
	// //::printf("%s\n", b58upkh);
	//::printf("%s\n", b58cpkh);
	//::printf("%s\n", b58upkh);
	//::printf("%s\n", b58cpsh);
	
	// write msg1
	//sprintf((char *)msg1, "ECCKEY: \n%s\n%s\n%s\n", priv_key_hex, b58cpkh, b58upkh);
	//sprintf((char *)msg1, "%s\n%s\n%s\n", priv_key_hex, b58cpkh, b58upkh);
	sprintf((char *)msg1, "%s\n%s\n%s\n%s\n", priv_key_hex, b58cpkh, b58upkh, b58cpsh);
	
	// Point
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	
	const EC_POINT *pub = EC_KEY_get0_public_key(myecc);
	const EC_GROUP *group = EC_KEY_get0_group(myecc);
	
	EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, NULL);
	
	char *pubx;
	char *pubx_str_lowercase;
	//char *puby;
	pubx = BN_bn2hex(x);
	//puby = BN_bn2hex(y);
	//pubx = strupr(pubx);
	
	//::printf("PointX: \n%s \n", pubx);
	//::printf("PointY: %s\n", puby);
	
	// Lowercase str
	pubx_str_lowercase = pubx;// copy str
	pubx_str_lowercase = _strlwr(pubx_str_lowercase);// Use the strlwr() to Transform an Uppercase String into a Lowercase One 
	
	//::printf("PointX: \n%s\n", pubx_str_lowercase);
	
	// write msg2
	sprintf((char *)msg2, "%s\n", pubx_str_lowercase);
	
}


int main(int argc, char *argv[])
{
	unsigned long keys_cnt = 0;
	unsigned long keys_max = 1000;
	uint32_t slp = 2000;
	bool write_px = true;
	float percprog = 0.00f;
	
	// many keys
	keys_max = keys_max * 100;
	
	::printf("Bitcoin Key Maker v. %4s\n", RELEASE);
	::printf("Please Wait... Make %u Keys\n", keys_max);
	SleepMillis(slp);
	
	
	OpenSSL_add_all_algorithms();
	
	
	EC_KEY *myecc = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (myecc == NULL)
		::printf("main() : EC_KEY_new_by_curve_name failed \n");
	
	unsigned char b58up2pkh[35];
	unsigned char b58cp2pkh[35];
	unsigned char b58cp2sh[35];
	unsigned char Out_msg1[512];
	unsigned char Out_msg2[512];
	
	string outputFile = "OutKeys.txt";
	string outputFile2 = "OutPointsX.txt";
	
	// write to file
	FILE *f = stdout;
	f = fopen(outputFile.c_str(), "a");
	if (f == NULL) {
		::printf("[error] Cannot open file '%s' for writing! \n", outputFile.c_str());
		f = stdout;
		return false;
	}
	
	// write to file 2
	FILE *f2 = stdout;
	if (write_px) {
		f2 = fopen(outputFile2.c_str(), "a");
		if (f2 == NULL) {
			::printf("[error] Cannot open file '%s' for writing! \n", outputFile2.c_str());
			f2 = stdout;
			return false;
		}
	}
	
	while (keys_cnt < keys_max) {
		
		// Make New Key
		bool newKey = GetPrivKey(myecc);
		int crAddr = 0;
		
		if (newKey){
			crAddr = CreateAddress(myecc, b58up2pkh, b58cp2pkh, b58cp2sh);
		}
		
		if (crAddr) {
			PrintAddress(myecc, b58up2pkh, b58cp2pkh, b58cp2sh, Out_msg1, Out_msg2);
		}

		// Output data to file
		fprintf(f, "%s", Out_msg1);// write to file
		if (write_px) fprintf(f2, "%s", Out_msg2);
		
		keys_cnt++;
		
		// Progres 
		if (keys_cnt % 10 == 0) {
			percprog = (float)keys_cnt * 100 / keys_max;
			::printf("Keys nb: %lu Progres: %0.1f%% \r", keys_cnt, percprog);
		}
	}
	
	::printf("Key generation completed %0.1f%% \r", percprog);
	
	SleepMillis(slp);
	
	fclose(f);
	if (write_px) fclose(f2);
	
	EC_KEY_free(myecc);
	
	return 0;
}

