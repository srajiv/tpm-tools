#include "tpm_seal.h"
#include "tpm_unseal.h"
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

enum tpm_errors {
	ENOTSSHDR = 0,
	EWRONGTSSTAG,
	EWRONGEVPTAG,
	EWRONGDATTAG,
	EWRONGKEYTYPE,
}; 

enum tspi_errors {
	ETSPICTXCREAT = 0,
	ETSPICTXCNCT,
	ETSPICTXCO,
	ETSPICTXLKBU,
	ETSPICTXLKBB,
	ETSPISETAD,
	ETSPIGETPO,
	ETSPIPOLSS,
	ETSPIDATU,
};

#define TSPI_FUNCTION_NAME_MAX 30
char tspi_error_strings[][TSPI_FUNCTION_NAME_MAX]= { 
				"Tspi_Context_Create",
				"Tspi_Context_Connect",
				"Tspi_Context_CreateObject",
				"Tspi_Context_LoadKeyByUUID",
				"Tspi_Context_LoadKeyByBlob",
				"Tspi_SetAttribData",
				"Tspi_GetPolicyObject",
				"Tspi_Policy_SetSecret",
				"Tspi_Data_Unseal" 
};

#define MAX_LINE_LEN 66
#define TSSKEY_DEFAULT_SIZE 559
#define EVPKEY_DEFAULT_SIZE 312
static const TSS_UUID SRK_UUID = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 1 } };

int tpm_errno;

int tpmUnsealFile( char* fname, unsigned char** tss_data, int* tss_size ) {

	int i, rc, tmpLen=0, tssLen=0, evpLen=0, datLen=0;
	char* rcPtr;
	char data[MAX_LINE_LEN];
	char *tssKeyData = NULL;
	int tssKeyDataSize = 0;
	char *evpKeyData = NULL;
	int evpKeyDataSize = 0;
	FILE* fd;
	struct stat stats;
        TSS_HCONTEXT hContext;
        TSS_HENCDATA hEncdata;
        TSS_HKEY hSrk, hKey;
        TSS_HPOLICY hPolicy;
        UINT32 symKeyLen;
        BYTE *symKey;

	unsigned char* res_data;
	int res_size;

	if ( tss_data == NULL || tss_size == NULL ) {
		rc = -2;
		tpm_errno = EINVAL;
		goto tss_out;
	}

	*tss_data = NULL;
	*tss_size = 0;

	if ((rc = stat(fname, &stats))) {
		tpm_errno = errno;
		goto tss_out;
	}	

	if ((fd = fopen(fname, "r")) == NULL){
		tpm_errno = errno;
		rc = -1;
		goto tss_out;
	}

        /* test file header for TSS */
	fgets(data, sizeof(data), fd);
        if (strncmp(data, TPMSEAL_HDR_STRING, strlen(TPMSEAL_HDR_STRING)) != 0) {
		rc = -2;
		tpm_errno = ENOTSSHDR;
		goto tss_out;
	}		
	tmpLen+=strlen(data); //TSS_HEADER

	fgets(data, sizeof(data), fd);
	if (strncmp(data, TPMSEAL_TSS_STRING, strlen(TPMSEAL_TSS_STRING)) != 0) {
		rc = -2;
		tpm_errno = EWRONGTSSTAG;
		goto tss_out_closefile;
	}
	tmpLen+=strlen(data); //TSS_STRING

      	/* retrieve the TSS key used to Seal */
	if ( (tssKeyData = malloc( TSSKEY_DEFAULT_SIZE )) == NULL) {
		tpm_errno = ENOMEM;
		rc = -1;
		goto tss_out_closefile;
	}

	tssKeyDataSize = TSSKEY_DEFAULT_SIZE;

        while ((rcPtr = fgets(data, sizeof(data), fd)) != NULL &&
		strncmp( data, TPMSEAL_EVP_STRING, strlen(TPMSEAL_EVP_STRING)) != 0 ) {
		int i = 0;
		tmpLen+=strlen(data); //Line of data

		if ( ( tssLen + strlen(data)/2 ) > tssKeyDataSize ) {
			printf( "Realloc req: %d %d %d\n", tssLen, strlen(data), tssKeyDataSize);
			rcPtr = realloc( tssKeyData, tssKeyDataSize + strlen(data));
			if ( rcPtr == NULL ) {
				tpm_errno = ENOMEM;
				rc = -1;
				goto tss_out_closefile;
			}
			tssKeyData = rcPtr;
			tssKeyDataSize += strlen(data);
		}

                while (data[i] != '\0' && data[i] != '\n' ) {
       	               	int val;
			sscanf(data + i, "%02x", &val);
			sprintf(tssKeyData + tssLen++, "%c", 0xFF & val);
               	        i += 2;
		}
        }

	if ( rcPtr == NULL ) {
		rc = -2;
		tpm_errno = EWRONGEVPTAG;
		goto tss_out_closefile;
	}
	tmpLen+= strlen(data);  //EVP_STRING

	fgets(data, sizeof(data), fd);
	if( strncmp(data, TPMSEAL_KEYTYPE_SYM, strlen(TPMSEAL_KEYTYPE_SYM)) != 0 ) {
		rc = -2;
		tpm_errno = EWRONGKEYTYPE;
		goto tss_out_closefile;
	}
	tmpLen+=strlen(data); //KEYTYPE_STRING

        /* retrieve the sealed EVP symmetric key used for encryption */
	if ( (evpKeyData = malloc( EVPKEY_DEFAULT_SIZE )) == NULL) {
		tpm_errno = ENOMEM;
		rc = -1;
		goto tss_out_closefile;
	}

	evpKeyDataSize = EVPKEY_DEFAULT_SIZE;

       	while ( (rcPtr=fgets(data, sizeof(data), fd)) != NULL &&
		strncmp(data, TPMSEAL_ENC_STRING, strlen(TPMSEAL_ENC_STRING)) !=0 ) {
		int i = 0;
		tmpLen+=strlen(data); //Line of data

		if ( ( evpLen + strlen(data)/2 ) > evpKeyDataSize ) {
			printf( "Realloc req %d %d %d\n", evpLen, strlen(data), evpKeyDataSize);
			rcPtr = realloc( evpKeyData, evpKeyDataSize + strlen(data));
			if ( rcPtr == NULL ) {
				tpm_errno = ENOMEM;
				rc = -1;
				goto tss_out_closefile;
			}
			evpKeyData = rcPtr;
			evpKeyDataSize += strlen(data);
		}

		while (data[i] != '\0' && data[i] != '\n') {
			int val;
			sscanf(data + i, "%02x", &val);
			sprintf(evpKeyData + evpLen++, "%c", 0xFF & val);
			i+= 2;
		}
	}

	if ( rcPtr == NULL ) {
		rc = -2;
		tpm_errno = EWRONGDATTAG;
		goto tss_out_closefile;
	}

	tmpLen+=strlen(data); //ENC_STRING
	/* Unseal */
	if ((rc=Tspi_Context_Create(&hContext)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCREAT;
		goto tss_out_closefile;
	}

	if ((rc=Tspi_Context_Connect(hContext, NULL)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCNCT;
		goto tss_out_closeall;
	}
			
	if ((rc=Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_ENCDATA,
					TSS_ENCDATA_SEAL,
					&hEncdata)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCO;
		goto tss_out_closeall;
	}
	        
	if ((rc=Tspi_SetAttribData(hEncdata,
				TSS_TSPATTRIB_ENCDATA_BLOB,
				TSS_TSPATTRIB_ENCDATABLOB_BLOB,
				evpLen, evpKeyData)) != TSS_SUCCESS) {
		tpm_errno = ETSPISETAD;
		goto tss_out_closeall;
	}

        if ((rc=Tspi_GetPolicyObject(hEncdata, TSS_POLICY_USAGE, 
					&hPolicy)) != TSS_SUCCESS) {
		tpm_errno = ETSPIGETPO;
		goto tss_out_closeall;
	}

        if ((rc=Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_PLAIN, 
					strlen(TPMSEAL_SECRET), 
					TPMSEAL_SECRET)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out_closeall;
	}

        if ((rc=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, 
					SRK_UUID, &hSrk)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXLKBU;
		goto tss_out_closeall;
	}

	/* This is the failure point if trying to unseal data on a differnt TPM */
        if ((rc=Tspi_Context_LoadKeyByBlob(hContext, hSrk, tssLen, 
					tssKeyData, &hKey)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXLKBB;
		goto tss_out_closeall;
	}

	if ((rc=Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)) 
		!= TSS_SUCCESS) {
		tpm_errno = ETSPIGETPO;
		goto tss_out_closeall;
	}

	if ((rc=Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_PLAIN, 
					strlen(TPMSEAL_SECRET), 
					TPMSEAL_SECRET)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out_closeall;
	}

        if ((rc=Tspi_Data_Unseal(hEncdata, hKey, &symKeyLen,
               	             &symKey)) != TSS_SUCCESS) {
		tpm_errno = ETSPIDATU;
		goto tss_out_closeall;
	}

	res_data = malloc(stats.st_size-tmpLen);
	if ( res_data == NULL ) {
		rc = -1;
		tpm_errno = ENOMEM;
		goto tss_out_closeall;
	}
	res_size = 0;
        /* Decrypt */
        EVP_CIPHER_CTX ctx;
        EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), symKey, TPMSEAL_IV);
       	/* retrieve the encrypted data needed */
        while (fgets(data, sizeof(data), fd) != NULL && 
		strncmp(data, TPMSEAL_FTR_STRING, strlen(TPMSEAL_FTR_STRING)) != 0) {
		int i = 0;
		datLen = 0;
               	while (data[i] != '\0' && data[i] != '\n') {
                        int val;
       	               	sscanf(data + i, "%02x", &val);
                        sprintf(data + (i/2), "%c", 0xFF & val);
       	               	i += 2;
			datLen++;
       	        }
		EVP_DecryptUpdate(&ctx, res_data+res_size, 
					&tmpLen, data, datLen);
		res_size += tmpLen;
        }
        EVP_DecryptFinal(&ctx, res_data+res_size, &tmpLen);
	res_size += tmpLen;

tss_out_closeall:
	Tspi_Context_Close(hContext);
tss_out_closefile:
	fclose(fd);
tss_out:

	if ( evpKeyData )
		free(evpKeyData);
	if ( tssKeyData )
		free(tssKeyData);

	if ( rc  == 0 ) {
		*tss_data = res_data;
		*tss_size = res_size;
	}
	return rc;
}

void tpmUnsealShred(unsigned char* data, int size) {

	if ( data != NULL ) {
		memset( data, 0, size);
		free(data);
	}

}

char tpm_error_buf[512];
char * tpmUnsealStrerror(int rc) {

	switch(rc) {
		case 0:
			return "Success";
		case -1:
			return strerror(tpm_errno);
		case -2:
			switch(tpm_errno) {
				case EINVAL:
					return ("Must pass in valid data and size pointers");
				case ENOTSSHDR:
					return ("No TSS header present");
				case EWRONGTSSTAG:
					return ("Wrong TSS tag");
				case EWRONGEVPTAG:
					return ("Wrong EVP tag");
				case EWRONGDATTAG:
					return ("Wrong DATA tag");
				case EWRONGKEYTYPE:
					return ("Not a Symmetric EVP Key");
			}
		default:
			snprintf(tpm_error_buf, sizeof(tpm_error_buf), 
				"%s: 0x%08x - layer=%s, code=%04x (%d), %s", 
				tspi_error_strings[tpm_errno],
				rc, Trspi_Error_Layer(rc), 
				Trspi_Error_Code(rc), 
				Trspi_Error_Code(rc), 
				Trspi_Error_String(rc)); 
			return tpm_error_buf;
	}
	return "";
}
