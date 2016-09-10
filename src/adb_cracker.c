#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#define PBKDF2_HASH_ROUNDS 10000
#define PBKDF2_KEY_SIZE 256 	// bits
#define PBKDF2_SALT_SIZE 512 	// bits
#define UIVSTRLEN 32
#define SALTSTRLEN 128
#define BLOBSTRLEN 192
#define MAXN 64

int aes_dec(unsigned char* aes_key, unsigned char *ivec, unsigned char* encrypted_data, unsigned char** decrypted_data){
	AES_KEY key;
	int data_size = strlen(encrypted_data);
	if(AES_set_decrypt_key(aes_key, PBKDF2_KEY_SIZE, &key)){
		printf("Set decrypt AES key failed...\n");
		return 1;
	}
	unsigned char* data = (unsigned char*)calloc(data_size + 1, sizeof(unsigned char));
	AES_cbc_encrypt(encrypted_data, data, data_size, &key, ivec, AES_DECRYPT);
	data[data_size] = '\0';
	*decrypted_data = data;
	return 0;
}

int aes_enc(unsigned char* aes_key, unsigned char *ivec, unsigned char* encrypt_data, unsigned char** encrypted_data){
	AES_KEY key;
	int data_size = strlen(encrypt_data);
	if(AES_set_encrypt_key(aes_key, PBKDF2_KEY_SIZE, &key)){
		printf("Set encrypt AES key failed...\n");
		return 1;
	}
	unsigned char* data = (unsigned char*)calloc(data_size + 1, sizeof(unsigned char));
	AES_cbc_encrypt(encrypt_data, data, data_size, &key, ivec, AES_ENCRYPT);
	data[data_size] = '\0';
	*encrypted_data = data;
	return 0;
}

int gen_key(const char *pass, int pass_size, const unsigned char *userkey_salt,int salt_size, int rounds, unsigned char **out_key, int key_size) {

	unsigned char *key = (unsigned char *)calloc(key_size + 1, sizeof(unsigned char));

	int ret = PKCS5_PBKDF2_HMAC_SHA1(pass, pass_size, userkey_salt, salt_size, rounds, key_size, key);

	if (!ret) {
		printf("Create user key failed...\n");
		return ret;
	}
	key[key_size] = '\0';
	printf("Create user key success...\n");
	printf("The user key is: ");
	int i = 0;
	for(;i < key_size; i++)
		printf("%.2X", key[i]);
	printf("\n");
	*out_key = key;
	return ret;
}

int make_checksum(unsigned char* pw_bytes, int pw_size, unsigned char* salt, int salt_size, int rounds, unsigned char** out_checksum, int key_size) {
	unsigned char* checksum = (unsigned char *)calloc(key_size + 1, sizeof(unsigned char));
	int ret = PKCS5_PBKDF2_HMAC_SHA1(pw_bytes, pw_size, salt, salt_size, rounds, key_size, checksum);
	if (!ret) {
		printf("Create user key failed...\n");
		return ret;
	}
	checksum[key_size] = '\0';
	printf("Caculate checksum success...\n");
	printf("The checksum is: ");
	int i = 0;
	for(;i < PBKDF2_KEY_SIZE / 8; i++)
		printf("%.2X", checksum[i]);
	printf("\n");
	*out_checksum = checksum;
	return ret;
}

int hex_to_bytes(char *hex_string, int len, unsigned char** out_bytes){
	int new_len = len / 2;
	int i = 0;
	unsigned char *bytes = (unsigned char *)calloc(new_len + 1, sizeof(unsigned char));
	if(2 * new_len != len) {
		printf("Hex string must have an even number of digits!\n");
		return 1;
	}
//	printf("The transformed bytes are: ");
	for(; i < len; i += 2) {
		int tmp1 = hex_string[i] >= 'A' && hex_string[i] <= 'F' ? \
				hex_string[i] - 55 : hex_string[i] >= 'a' && hex_string[i] <= 'f' ?\
				hex_string[i] - 87 : hex_string[i] - '0';
		int tmp2 = hex_string[i+1] >= 'A' && hex_string[i+1] <= 'F' ? \
				hex_string[i+1] - 55 : hex_string[i+1] >= 'a' && hex_string[i+1] <= 'f' ?\
				hex_string[i+1] - 87 : hex_string[i+1] - '0';
		int tmp = 16 * tmp1 + tmp2;
		bytes[i/2] = (unsigned char) tmp;
//		printf("%.2X", bytes[i/2]);
	}
	bytes[new_len] = '\0';
//	printf("\nstrlen(bytes) = %d\n", strlen(bytes));
	*out_bytes = bytes;
	return 0;
}

void parse_blob(unsigned char* decrypt_blob, unsigned char** master_iv, int* master_iv_size, unsigned char** master_key, int* master_key_size, unsigned char** checksum, int* checksum_size){
	int i;
	int start = 0;
	int iv_size = decrypt_blob[start];
	printf("iv_size = %d\n", iv_size);
	if(iv_size != 16) {
		printf("Wrong iv_size, parse blob failed!!!\n");
		return;
	}

	unsigned char* m_iv = (unsigned char*)calloc(iv_size + 1, sizeof(unsigned char));
	start++;
	for(i = 0; i < iv_size; i++){
		m_iv[i] = decrypt_blob[start+i];
	}
	start += iv_size;

	int mk_size = decrypt_blob[start];
	printf("mk_size = %d\n", mk_size);
	if(mk_size != 32) {
		printf("Wrong mk_size, parse blob failed!!!\n");
		if(m_iv)
			free(m_iv);
		return;
	}
	unsigned char* mk = (unsigned char*)calloc(mk_size + 1, sizeof(unsigned char));
	start++;
	for(i = 0; i < mk_size; i++){
		mk[i] = decrypt_blob[start+i];
	}
	start += mk_size;

	int ck_size = decrypt_blob[start];
	printf("ck_size = %d\n", ck_size);
	if(ck_size != 32) {
		printf("Wrong ck_size, parse blob failed!!!\n");
		if(m_iv)
			free(m_iv);
		if(mk)
			free(mk);
		return;
	}
	unsigned char* cksum = (unsigned char*)calloc(ck_size + 1, sizeof(unsigned char));
	start++;
	for(i = 0; i < ck_size; i++){
		cksum[i] = decrypt_blob[start+i];
	}
	start += ck_size;

	*master_iv = m_iv;
	if(master_iv_size)
		*master_iv_size = iv_size;
	*master_key = mk;
	if(master_key_size)
		*master_key_size = mk_size;
	*checksum = cksum;
	if(checksum_size)
		*checksum_size = ck_size;
}

int parse_backup_file(char* path, int* version, int* compressed, int* encrypted, unsigned char** userkey_salt, unsigned char** checksum_salt, unsigned char** user_iv, unsigned char** encrypted_blob) {
	char android[8] = { 0 }; 		// line1
	char backup[7] = { 0 };			// line1
	int ver;						// line2
	int cpr;						// line3
	char enc_name[8] = { 0 };		// line4
	char *usalt = NULL;				// line5
	char *csalt = NULL;				// line6
	int rounds;						// line7
	char *uiv = NULL;				// line8
	char *eblob = NULL;				// line9

	int ret = 1;
	FILE *fin;
	fin = fopen(path, "r");
	if(!fin) {
		fprintf(stderr, "File %s not found!!!\n", path);
		return ret;
	}
	fseek(fin,0L,SEEK_SET);
	fscanf(fin, "%s", android);
//	printf("%s\n", android);
	fscanf(fin, "%s", backup);
//	printf("%s\n", backup);
	if(strncmp(android, "ANDROID", strlen(android)) && strncmp(backup, "BACKUP", strlen(backup))){
		fprintf(stderr, "Not a Android backup file!!!\n");
		return ret;
	}
	fscanf(fin, "%d", &ver);
	if(version)
		*version = ver;
//	printf("%d\n", ver);
	fscanf(fin, "%d", &cpr);
	fscanf(fin, "%s", enc_name);
	if(!strncmp(enc_name, "None", strlen(enc_name))){
		fprintf(stdout, "File %s is not encrypted!!!\n", path);
		if(encrypted)
			*encrypted = 0;
		return 2;
	}
	if(encrypted)
		*encrypted = 1;
	usalt = (char*)calloc(SALTSTRLEN + 1, sizeof(char));
	fscanf(fin, "%s", usalt);
//	printf("%s\n", usalt);
	csalt = (char*)calloc(SALTSTRLEN + 1, sizeof(char));
	fscanf(fin, "%s", csalt);
//	printf("%s\n", csalt);
	fscanf(fin, "%d", &rounds);
	uiv = (char*)calloc(UIVSTRLEN + 1, sizeof(char));
	fscanf(fin, "%s", uiv);
//	printf("%s\n", uiv);
	eblob = (char*)calloc(BLOBSTRLEN + 1, sizeof(char));
	fscanf(fin, "%s", eblob);
//	printf("%s\n", eblob);
	fclose(fin);

	if(hex_to_bytes(usalt, SALTSTRLEN, userkey_salt)) {
		fprintf(stderr, "User key salt transferred to bytes failed|");
		goto bail;
	}
	if(hex_to_bytes(csalt, SALTSTRLEN, checksum_salt)) {
		fprintf(stderr, "Checksum  salt transferred to bytes failed|");
		goto bail;
	}

	if(hex_to_bytes(uiv, UIVSTRLEN, user_iv)) {
		fprintf(stderr, "User key IV salt transferred to bytes failed|");
		goto bail;
	}

	if(hex_to_bytes(eblob, BLOBSTRLEN, encrypted_blob)) {
		fprintf(stderr, "User key salt transferred to bytes failed|");
		goto bail;
	}

	ret = 0;
bail:
	if(usalt)
		free(usalt);
	if(csalt)
		free(csalt);
	if(uiv)
		free(uiv);
	if(eblob)
		free(eblob);
	return ret;
}

int main() {
	char *pass = "123456";
	char *path = "/Users/wangli/Desktop/backup.ab";
//	char *salt = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40";
//	printf("Salt string length = %d\n", strlen(salt));
	unsigned char* u_salt = NULL;
	unsigned char *c_salt = NULL;
	unsigned char *u_iv = NULL;
	unsigned char *enc_blob = NULL;

	unsigned char *dec_blob = NULL;
	unsigned char *uk = NULL;

	if(parse_backup_file(path, NULL, NULL, NULL, &u_salt, &c_salt, &u_iv, &enc_blob)) {
		fprintf(stderr, "Parse file %s failed!!!\n", path);
		exit(-1);
	}
	int data_size = BLOBSTRLEN / 2;
	if(!gen_key(pass, strlen(pass), u_salt, SALTSTRLEN / 2, PBKDF2_HASH_ROUNDS, &uk, PBKDF2_KEY_SIZE / 8))
		exit(-1);

	aes_dec(uk, u_iv, enc_blob, &dec_blob);
	printf("The dec_blob is: ");
	int i;
	for(i = 0; i < data_size; i++)
		printf("%.2X", dec_blob[i]);
	printf("\n");
	unsigned char* master_key = NULL;
	unsigned char* master_iv = NULL;
	unsigned char* checksum = NULL;
	int iv_size;
	int mk_size;
	int ck_size;
	parse_blob(dec_blob, &master_iv, &iv_size, &master_key, &mk_size, &checksum, &ck_size);
	printf("The master_iv is: ");
	for(i = 0; i < iv_size; i++)
		printf("%.2X", master_iv[i]);
	printf("\n");
	printf("The master_key is: ");
	for(i = 0; i < mk_size; i++)
		printf("%.2X", master_key[i]);
	printf("\n");
	printf("The checksum is: ");
	for(i = 0; i < ck_size; i++)
		printf("%.2X", checksum[i]);
	printf("\n");
	printf("The cksalt is: ");
	for(i = 0; i < SALTSTRLEN / 2; i++)
		printf("%.2X", c_salt[i]);
	printf("\n");
	unsigned char *cksum = NULL;
	make_checksum(master_key, mk_size, c_salt, SALTSTRLEN / 2, PBKDF2_HASH_ROUNDS, &cksum, PBKDF2_KEY_SIZE / 8);
	if(strncmp(cksum, checksum, PBKDF2_KEY_SIZE / 8)) {
		printf("Wrong user password :%s!!!\n", pass);
		exit(-1);
	}
	printf("Password %s is right!!!\n", pass);
	free(u_salt);
	free(uk);
	return 0;
}
