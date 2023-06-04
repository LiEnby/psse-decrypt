#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "aes.h"
#include "md5.c"

#ifdef MAX_PATH
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#else
#ifndef PATH_MAX
#define PATH_MAX (0x7FFF)
#endif	
#endif


#define DEBUG 1

#define PSSE_BLOCK_SIZE (0x8000)
#define PSSE_SIG_BLOCK_SIZE (0x80000)
#define PSSE_SIG_SIZE (0x400)

#define AES_KEY_SIZE (0x10)
#define AES_IV_SIZE (0x10)

const uint8_t header_iv[AES_IV_SIZE]			=	{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}; // IV for the encrypted PSSE Header
const uint8_t header_key[AES_KEY_SIZE]			=	{0x4E, 0x29, 0x8B, 0x40, 0xF5, 0x31, 0xF4, 0x69, 0xD2, 0x1F, 0x75, 0xB1, 0x33, 0xC3, 0x07, 0xBE}; // Key used to decrypt the encrypted PSSE Header

const uint8_t runtime_title_key[AES_KEY_SIZE]	=	{0xA8, 0x69, 0x3C, 0x4D, 0xF0, 0xAE, 0xED, 0xBC, 0x9A, 0xBF, 0xD8, 0x21, 0x36, 0x92, 0x91, 0x2D}; // Header used to decrypt runtime libaries, eg. Sce.PlayStation.Core.dll.
const uint8_t header_key_psmdev[AES_KEY_SIZE]	=	{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}; // Key used to decrypt the encrypted PSSE Header in PSM dev,

const char* runtime_content_id			=	"IP9100-NPXS10074_00-0000000000000000";

static char title_content_id[0x30];
static uint8_t title_iv[AES_IV_SIZE];
static uint8_t title_key[AES_KEY_SIZE];

// psse header
typedef struct psse_header{
	char     magic[0x4];
	uint32_t version;
	uint64_t file_size;
	uint32_t psse_type;
	char     content_id[0x2C];
	uint8_t  md5_hash[0x10];
	uint8_t  file_name[0x20];
	uint8_t  file_iv[0x10];
	uint8_t  unk[0x600];
} psse_header;

// rif header
typedef struct ScePsmDrmLicense {
  char magic[0x8];             
  uint32_t unk1;               
  uint32_t unk2;               
  uint64_t account_id;                
  uint32_t unk3;               
  uint32_t unk4;               
  uint64_t start_time;         
  uint64_t expiration_time;    
  uint8_t activation_checksum[0x20];    
  char content_id[0x30];       
  uint8_t unk5[0x80];          
  uint8_t unk6[0x20];
  uint8_t key[0x10];
  uint8_t signature[0x1D0];
  uint8_t rsa_signature[0x100]; 
} ScePsmDrmLicense;

// psse_block_ref struct
typedef struct psse_block_ref{
	uint8_t block_data[PSSE_BLOCK_SIZE];
	size_t block_size;
} psse_block_ref;

typedef struct decrypted_file{
	uint8_t* data;
	size_t file_size;
} decrypted_file;

// Debug print buffer contents
void print_buffer(char* buffer_title, uint8_t* buffer, size_t buffer_sz){
	printf("[*] %s: ", buffer_title);
	for(int i = 0; i < buffer_sz; i++) {
		printf("%02X", buffer[i]);
	}
	printf("\n");	
}

// Convert a path to one for whatever OS your using.
void fix_paths(char* path){
	size_t sz = strlen(path);
	for(int i = 0; i < sz; i++){
		#ifdef _WIN32
		if(path[i] == '/')
		#else
		if(path[i] == '\\')
		#endif
		{
			#ifdef _WIN32
			path[i] = '\\';
			#else
			path[i] = '/';
			#endif
		}
	}
}

// Convert a path to one for whatever OS your using.
int is_dir(char* path){
	size_t sz = strlen(path);
	if(path[sz] == '/' || path[sz] == '\\')
		return 1;
	return 0;
}

// Reads title key and content id from a rif
// returns <0 on fail, 0 on success.
int read_rif(char* rif_path){
	ScePsmDrmLicense rif;

	FILE* rif_fd = fopen(rif_path, "rb");
	if(rif_fd == NULL){
		return -1;
	}	
	fread(&rif, sizeof(ScePsmDrmLicense), 1, rif_fd);
	fclose(rif_fd);
	
	// Read important stuff.
	strncpy(title_content_id, rif.content_id, sizeof(title_content_id));	
	memcpy(title_key, rif.key, sizeof(title_key));

	if(strlen(title_content_id) != 0x24){
		return -2;
	}

	return 0x0;
}

// Returns the total filesize of a file.
size_t get_file_size(char* file_path){
	FILE* get_size_fd = fopen(file_path, "rb");
	fseek(get_size_fd, 0, SEEK_END);
	size_t size = ftell(get_size_fd);
	fclose(get_size_fd);
	return size;
}

// Calculate IV for this block.
uint8_t* roll_iv(uint64_t block_id) {
	uint8_t* new_iv = (uint8_t*)malloc(sizeof(title_iv));
	
	memset(new_iv,0x00, sizeof(title_iv));
	memcpy(new_iv, &block_id, sizeof(uint64_t));
	for(int i = 0; i < sizeof(title_iv); i++){
		new_iv[i] = new_iv[i] ^ title_iv[i];
	}
	return new_iv;
}

// Decrypts a specific block inside a PSSE file.
psse_block_ref decrypt_block(FILE* psse_file, uint64_t block_id, uint64_t total_blocks, uint32_t file_size){
	psse_block_ref ref;
	memset(&ref, 0x00, sizeof(psse_block_ref));
	
	uint8_t* new_iv = roll_iv(block_id);
	uint64_t block_loc = block_id * PSSE_BLOCK_SIZE;
    size_t total_read = PSSE_BLOCK_SIZE;
    uint64_t trim_to = total_read;
    
    if(block_id == 0){  // Skip to filedata
        block_loc = sizeof(psse_header);
        total_read -= sizeof(psse_header);
        trim_to = total_read;
	}
    else if(block_loc % PSSE_SIG_BLOCK_SIZE == 0){ // Skip signature block
        block_loc += PSSE_SIG_SIZE;
        total_read -= PSSE_SIG_SIZE;
        trim_to = total_read;
	}
    
    uint64_t rd_amt = ((block_loc - sizeof(psse_header)) - (PSSE_SIG_SIZE*(block_loc / PSSE_SIG_BLOCK_SIZE))); // Total amount of bytes read so far.
    
    if (block_id >= total_blocks) { // Is this the last block?
        total_read = file_size - rd_amt;
        trim_to = total_read;
        total_read += ((AES_BLOCK_SIZE) - (total_read % (AES_BLOCK_SIZE)));
	}
	
	uint8_t* block_data = malloc(total_read);

    fseek(psse_file, block_loc, SEEK_SET);
	fread(block_data, total_read, 0x1, psse_file);
	ref.block_size = trim_to;
	
	// Decrypt block
	uint32_t aes_game_ctx[0x3C];
	aes_key_setup(title_key, aes_game_ctx, 0x80);	
	aes_decrypt_cbc(block_data, total_read, ref.block_data, aes_game_ctx, 0x80, new_iv);

	free(block_data);
	free(new_iv);
	return ref;
}

// returns decrypted data on success, empty filesize on error
decrypted_file decrypt_file(char* psse_file){
	size_t total_filesize = get_file_size(psse_file);
	uint64_t total_blocks = (total_filesize / 0x8000);

	uint8_t title_key_copy[sizeof(title_key)];

	uint32_t aes_header_ctx[0x3C];
	
	FILE* psse_file_fd = fopen(psse_file, "rb");

	decrypted_file plaintext_file;
	memset(&plaintext_file, 0x00, sizeof(decrypted_file));
	
	psse_header file_psse_header;
	memset(&file_psse_header, 0x00, sizeof(psse_header));
	fread(&file_psse_header, sizeof(psse_header), 0x1, psse_file_fd);

	#ifdef DEBUG
		printf("[*] Decrypting: %s\n", psse_file);
	#endif	
		
	// Check magic number
	if(!((strncmp(file_psse_header.magic, "PSSE", 0x4) == 0) || (strncmp(file_psse_header.magic, "PSME", 0x4) == 0))){
		#ifdef DEBUG
				printf("[*] %s Is not a valid PSSE file.\n", psse_file);
		#endif	
		return plaintext_file;
	}

	// Chceck version
	if(file_psse_header.version != 0x01){
		#ifdef DEBUG
				printf("[*] %s has unknown PSSE version %i.\n", psse_file, file_psse_header.version);
		#endif	
		return plaintext_file;
	}
	
	// Check psse type
	if(file_psse_header.psse_type != 0x01){
		#ifdef DEBUG
				printf("[*] %s has unknown PSSE type %i.\n", psse_file, file_psse_header.version);
		#endif	
		return plaintext_file;
	}
	
	int psm_dev = 0;
	
	// Check content id
	if(strlen(file_psse_header.content_id) == 0x24) {
		if(strcmp(file_psse_header.content_id, title_content_id) == 0){ // Retail PSM
			aes_key_setup(header_key, aes_header_ctx, 0x80);
		}
		else if(strcmp(file_psse_header.content_id, runtime_content_id)){ // Runtime Libary
			memcpy(title_key_copy, title_key, sizeof(title_key));
			memcpy(title_key, runtime_title_key, sizeof(title_key));
			aes_key_setup(header_key, aes_header_ctx, 0x80);
			psm_dev = 1;
		}
		else{ 
			return plaintext_file;
		}
	}
	else { // Debug PSM
		aes_key_setup(header_key_psmdev, aes_header_ctx, 0x80);
	}
	
	aes_decrypt_cbc(file_psse_header.file_iv, sizeof(title_iv), title_iv, aes_header_ctx, 0x80, header_iv);
		
	char* plaintext = malloc(file_psse_header.file_size);
	uintptr_t plaintext_ptr = 0;
	
	MD5Context md5_ctx;
	md5Init(&md5_ctx);
	
	for(int i = 0; i <= total_blocks; i++){
		psse_block_ref block_ref = decrypt_block(psse_file_fd, i, total_blocks, file_psse_header.file_size);
		
		md5Update(&md5_ctx, block_ref.block_data, block_ref.block_size);
		
		memcpy(plaintext+plaintext_ptr, block_ref.block_data, block_ref.block_size);
		plaintext_ptr += block_ref.block_size;
	}
	
	md5Finalize(&md5_ctx);
	
	if(memcmp(file_psse_header.md5_hash, md5_ctx.digest, 0x10) != 0){
		#ifdef DEBUG
			printf("[*] MD5 Hash did not match expected.\n");
			print_buffer("Got MD5", md5_ctx.digest, 0x10);
			print_buffer("Expected MD5", file_psse_header.md5_hash, 0x10);
		#endif
		return plaintext_file;
	}
	
	
	fclose(psse_file_fd);

	plaintext_file.data = plaintext;
	plaintext_file.file_size = file_psse_header.file_size;

	if(psm_dev){
		memcpy(title_key, title_key_copy, sizeof(title_key));
	}

	return plaintext_file;
}

int decrypt_all_files(char* application_folder, char* psse_list, size_t psse_list_sz){
	uint64_t start_point = 0;
	size_t sz = 0;
	
	char rel_path[PATH_MAX];
	for(uint64_t i = 0; i < psse_list_sz; i++){
		
		if(psse_list[i] == '\r' || psse_list[i] == '\n') {
			
			if (sz == 0){
				goto next;
			}

			char* cur_filename = (char*)malloc(sz+1);
			memset(cur_filename, 0x00, sz+1);
			strncpy(cur_filename, (psse_list+start_point), sz);
			
			memset(rel_path, 0x00, sizeof(rel_path));
			snprintf(rel_path, sizeof(rel_path), "%s\\%s", application_folder, cur_filename);			
			free(cur_filename);
			
			fix_paths(rel_path);
			
			if(is_dir(rel_path)){
				goto next;
			}
			
			decrypted_file dec_file = decrypt_file(rel_path);
			
			if(dec_file.data == NULL){
				#ifdef DEBUG
					printf("[*] Decryption failed.\n");
				#endif
				return -3;
			}
			
			// Write decrypted file to disk.
			FILE* dec_file_fd = fopen(rel_path, "wb");
			if(dec_file_fd == NULL){
				#ifdef DEBUG
					printf("[*] Failed to open %s for writing.\n", rel_path);
				#endif
				return -4;
			}
			fwrite(dec_file.data, dec_file.file_size, 0x1, dec_file_fd);
			fclose(dec_file_fd);

			free(dec_file.data);
			
			next:
			start_point = i+1;
			sz = 0;
			continue;
		}
		sz++;
	}
}

int main(int argc, char** argv)
{
	memset(title_content_id, 0x00, sizeof(title_content_id));
	memset(title_iv, 0x00, sizeof(title_iv));
	memset(title_key, 0x00, sizeof(title_key));

	if(argc <= 1){
		printf("PSSE Decryptor.\n");
		printf("Usage: %s <PSM_FOLDER>\n",argv[0]);
		return 0;
	}

	char* psm_folder = argv[1];
	
	char application_folder[PATH_MAX];
	char psse_list[PATH_MAX];
	char rif_file[PATH_MAX];
	
	snprintf(application_folder, PATH_MAX-1, "%s\\RO\\Application", psm_folder);	
	snprintf(psse_list, PATH_MAX-1, "%s\\psse.list", application_folder);
	snprintf(rif_file, PATH_MAX-1, "%s\\RO\\License\\FAKE.rif", psm_folder);
	
	fix_paths(application_folder);
	fix_paths(psse_list);
	fix_paths(rif_file);
	
	if(read_rif(rif_file) < 0){
		printf("[*] Unable to read RIF: %s\n", rif_file);
		return -1;
	}
	#ifdef DEBUG
		print_buffer("[*] Title Key", title_key, sizeof(title_key));
	#endif
	
	
	
	decrypted_file plaintext_psse_list = decrypt_file(psse_list);
	if(plaintext_psse_list.data == NULL){
		printf("[*] Decryption failed.\n");
		return -2;
	}
	
	// Write decrypted psse.list.
	FILE* psse_list_fd = fopen(psse_list, "wb");
	fwrite(plaintext_psse_list.data, plaintext_psse_list.file_size, 0x1, psse_list_fd);
	fclose(psse_list_fd);

	int res = decrypt_all_files(application_folder, plaintext_psse_list.data, plaintext_psse_list.file_size);
	if (res < 0){
		return res;
	}
	free(plaintext_psse_list.data);	
}