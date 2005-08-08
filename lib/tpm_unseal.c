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
#define TSSKEY_DATA_LEN 559
#define EVPKEY_DATA_LEN 268
#define HEADER "-----BEGIN TSS"
#define FOOTER "-----END TSS"
#define TSS_TAG "-----TSS KEY-----"
#define EVP_TAG "-----ENC KEY-----"
#define DAT_TAG "-----ENC DAT-----"
#define POLICY_SECRET "password"
static const TSS_UUID SRK_UUID = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 1 } };
static const char iv[8]="IBM SEAL";

int tpm_errno;

int tpmUnsealFile( char* fname, char** tss_data, int* tss_size ) {

	int rc, tmpLen=0, tssLen=0, evpLen=0, datLen=0;
	char* rcPtr;
	char data[MAX_LINE_LEN];
	char tssKeyData[TSSKEY_DATA_LEN];
	char evpKeyData[EVPKEY_DATA_LEN];
	FILE* fd;
	struct stat stats;
        TSS_HCONTEXT hContext;
        TSS_HENCDATA hEncdata;
        TSS_HKEY hSrk, hKey;
        TSS_HPOLICY hPolicy;
        UINT32 symKeyLen;
        BYTE *symKey;

	if ( tss_data == NULL || tss_size == NULL ) {
		rc = -2;
		tpm_errno = EINVAL;
		goto tss_out;
	}

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
        if (strncmp(data, HEADER, strlen(HEADER)) != 0) {
		rc = -2;
		tpm_errno = ENOTSSHDR;
		goto tss_out;
	}		
	tmpLen+=strlen(data);
	fgets(data, sizeof(data), fd);
	if (strncmp(data, TSS_TAG, strlen(TSS_TAG)) != 0) {
		rc = -2;
		tpm_errno = EWRONGTSSTAG;
		goto tss_out_closefile;
	}
	tmpLen+=strlen(data);
      	/* retrieve the TSS key used to Seal */
        while ((rcPtr = fgets(data, sizeof(data), fd)) != NULL &&
		strncmp( data, EVP_TAG, strlen(EVP_TAG)) != 0 ) {
		int i = 0;
		tmpLen+=strlen(data);
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

	tmpLen+=strlen(data);
        /* retrieve the sealed EVP symmetric key used for encryption */
       	while ( (rcPtr=fgets(data, sizeof(data), fd)) != NULL &&
		strncmp(data, DAT_TAG, strlen(DAT_TAG)) !=0 ) {
		int i = 0;
		tmpLen+=strlen(data);
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

	tmpLen+=strlen(data);
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
					strlen(POLICY_SECRET), 
					POLICY_SECRET)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out_closeall;
	}

        if ((rc=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, 
					SRK_UUID, &hSrk)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXLKBU;
		goto tss_out_closeall;
	}

	/* This step will fail if tried on the wrong machine */
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
					strlen(POLICY_SECRET), 
					POLICY_SECRET)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out_closeall;
	}

        if ((rc=Tspi_Data_Unseal(hEncdata, hKey, &symKeyLen,
               	             &symKey)) != TSS_SUCCESS) {
		tpm_errno = ETSPIDATU;
		goto tss_out_closeall;
	}

	*tss_data = malloc(stats.st_size-tmpLen);
	if ( *tss_data == NULL ) {
		rc = -1;
		tpm_errno = ENOMEM;
		goto tss_out_closeall;
	}
	*tss_size = 0;
        /* Decrypt */
        EVP_CIPHER_CTX ctx;
        EVP_DecryptInit(&ctx, EVP_des_cbc(), symKey, iv);
       	/* retrieve the encrypted data needed */
        while (fgets(data, sizeof(data), fd) != NULL && 
		strncmp(data, FOOTER, strlen(FOOTER)) != 0) {
		int i = 0;
		datLen = 0;
               	while (data[i] != '\0' && data[i] != '\n') {
                        int val;
       	               	sscanf(data + i, "%02x", &val);
                        sprintf(data + (i/2), "%c", 0xFF & val);
       	               	i += 2;
			datLen++;
       	        }
		EVP_DecryptUpdate(&ctx, (*tss_data)+(*tss_size), 
					&tmpLen, data, datLen);
		(*tss_size) += tmpLen;
        }
        EVP_DecryptFinal(&ctx, (*tss_data)+(*tss_size), &tmpLen);
	(*tss_size) += tmpLen;
	
tss_out_closeall:
	Tspi_Context_Close(hContext);
tss_out_closefile:
	fclose(fd);
tss_out:
	return rc;
}

void tpmUnsealShred(char* data, int size) {

	if ( data != NULL ) {
		memset( data, 0, size);
		free(data);
	}

}

char * tpmUnsealStrerror(int rc, char* str) {

	switch(rc) {
		case 0:
			return "Success";
		case -1:
			return strerror(tpm_errno);
		case -2:
			switch(tpm_errno) {
				case EINVAL:
					return "Must pass in valid data and size pointers";
				case ENOTSSHDR:
					return "No TSS header present";
				case EWRONGTSSTAG:
					return "Wrong TSS tag";
				case EWRONGEVPTAG:
					return "Wrong EVP tag";
				case EWRONGDATTAG:
					return "Wrong DATA tag";
			}
		default:
			if ( str ) {
				sprintf(str, 
					"%s: 0x%08x - layer=%s, code=%04x (%d), %s", 
					tspi_error_strings[tpm_errno],
					rc, Trspi_Error_Layer(rc), 
					Trspi_Error_Code(rc), 
					Trspi_Error_Code(rc), 
					Trspi_Error_String(rc)); 
				return str;
			}
			return tspi_error_strings[tpm_errno];
	}
	return "";
}
