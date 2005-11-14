/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

#include "tpm_tspi.h"
#include "tpm_seal.h"
#include "tpm_unseal.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

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

int tpm_errno;

int tpmUnsealFile( char* fname, unsigned char** tss_data, int* tss_size ) {

	int start, rc, rcLen=0, tssLen=0, evpLen=0, datLen=0;
	char* rcPtr;
	char data[MAX_LINE_LEN];
	char *tssKeyData = NULL;
	int tssKeyDataSize = 0;
	char *evpKeyData = NULL;
	int evpKeyDataSize = 0;
	struct stat stats;
        TSS_HCONTEXT hContext;
        TSS_HENCDATA hEncdata;
        TSS_HKEY hSrk, hKey;
        TSS_HPOLICY hPolicy;
        UINT32 symKeyLen;
        BYTE *symKey;

	unsigned char* res_data;
	int res_size;

	BIO *bdata = NULL, *b64 = NULL;

	if ( tss_data == NULL || tss_size == NULL ) {
		rc = TPMSEAL_STD_ERROR;
		tpm_errno = EINVAL;
		goto out;
	}

	*tss_data = NULL;
	*tss_size = 0;

	if ((rc = stat(fname, &stats))) {
		tpm_errno = errno;
		goto out;
	}	

	if((bdata = BIO_new_file(fname, "r")) == NULL ) {
		tpm_errno = errno;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

        /* test file header for TSS */
	BIO_gets(bdata, data, sizeof(data));
        if (strncmp(data, TPMSEAL_HDR_STRING, 
			strlen(TPMSEAL_HDR_STRING)) != 0) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = ENOTSSHDR;
		goto out;
	}		

	/* looking for TSS Key Header */
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp(data, TPMSEAL_TSS_STRING, 
			strlen(TPMSEAL_TSS_STRING)) != 0) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = EWRONGTSSTAG;
		goto out;
	}

      	/* retrieve the TSS key used to Seal */
	if ( (tssKeyData = malloc( TSSKEY_DEFAULT_SIZE )) == NULL) {
		tpm_errno = ENOMEM;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	tssKeyDataSize = TSSKEY_DEFAULT_SIZE;

	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
		tpm_errno = EAGAIN;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	start = BIO_tell(bdata);

	bdata = BIO_push( b64, bdata );

        while ((rcLen=BIO_read(bdata, data, sizeof(data))) > 0 ) {
		if ( ( tssLen + rcLen ) > tssKeyDataSize ) {
			rcPtr = realloc( tssKeyData, tssKeyDataSize + rcLen);
			if ( rcPtr == NULL ) {
				tpm_errno = ENOMEM;
				rc = TPMSEAL_STD_ERROR;
				goto out;
			}
			tssKeyData = rcPtr;
			tssKeyDataSize += rcLen;
		}
		memcpy( tssKeyData + tssLen, data, rcLen );
		tssLen += rcLen;
        }
	bdata = BIO_pop(b64);
	BIO_free(b64);
	b64 = NULL;

	start += ((tssLen * 4)+2)/3; //add base64 chars
	start += 3 - ((tssLen * 4)%3); //add base64 pad
	start += ((((tssLen * 4)+2)/3)+63)/64; //add base64 nl

	/* looking for EVP Key Header */
	BIO_seek(bdata, start);
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp( data, TPMSEAL_EVP_STRING, 
			strlen(TPMSEAL_EVP_STRING)) != 0 ) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = EWRONGEVPTAG;
		goto out;
	}

	BIO_gets(bdata, data, sizeof(data));
	if( strncmp(data, TPMSEAL_KEYTYPE_SYM, 
			strlen(TPMSEAL_KEYTYPE_SYM)) != 0 ) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = EWRONGKEYTYPE;
		goto out;
	}

        /* retrieve the sealed EVP symmetric key used for encryption */
	if ( (evpKeyData = malloc( EVPKEY_DEFAULT_SIZE )) == NULL) {
		tpm_errno = ENOMEM;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	evpKeyDataSize = EVPKEY_DEFAULT_SIZE;

	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
    tpm_errno = EAGAIN;
    rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	start = BIO_tell( bdata );
	
	bdata = BIO_push( b64, bdata );
        while ((rcLen=BIO_read(bdata, data, sizeof(data))) > 0 ) {
		if ( ( evpLen + rcLen ) > evpKeyDataSize ) {
			rcPtr = realloc( evpKeyData, evpKeyDataSize + rcLen);
			if ( rcPtr == NULL ) {
				tpm_errno = ENOMEM;
				rc = TPMSEAL_STD_ERROR;
				goto out;
			}
			evpKeyData = rcPtr;
			evpKeyDataSize += rcLen;
		}
		memcpy( evpKeyData + evpLen, data, rcLen );
		evpLen += rcLen;
        }
	bdata = BIO_pop(b64);
	BIO_free(b64);
	b64 = NULL;

	start += ((evpLen * 4)+2)/3; //add base64 chars
	start += 3 - ((evpLen * 4)%3); //add base64 pad
	start += ((((evpLen * 4)+2)/3)+63)/64; //add base64 nl

	/* looking for ENC Data Header */
	BIO_seek(bdata, start);
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp( data, TPMSEAL_ENC_STRING, 
			strlen(TPMSEAL_ENC_STRING)) != 0 ) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = EWRONGDATTAG;
		goto out;
	}
	
	/* Unseal */
	if ((rc=Tspi_Context_Create(&hContext)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCREAT;
		goto out;
	}

	if ((rc=Tspi_Context_Connect(hContext, NULL)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCNCT;
		goto tss_out;
	}
			
	if ((rc=Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_ENCDATA,
					TSS_ENCDATA_SEAL,
					&hEncdata)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCO;
		goto tss_out;
	}
	        
	if ((rc=Tspi_SetAttribData(hEncdata,
				TSS_TSPATTRIB_ENCDATA_BLOB,
				TSS_TSPATTRIB_ENCDATABLOB_BLOB,
				evpLen, evpKeyData)) != TSS_SUCCESS) {
		tpm_errno = ETSPISETAD;
		goto tss_out;
	}

        if ((rc=Tspi_GetPolicyObject(hEncdata, TSS_POLICY_USAGE, 
					&hPolicy)) != TSS_SUCCESS) {
		tpm_errno = ETSPIGETPO;
		goto tss_out;
	}

        if ((rc=Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_PLAIN, 
					strlen(TPMSEAL_SECRET), 
					TPMSEAL_SECRET)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out;
	}

        if ((rc=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, 
					SRK_UUID, &hSrk)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXLKBU;
		goto tss_out;
	}

	/* Failure point if trying to unseal data on a differnt TPM */
        if ((rc=Tspi_Context_LoadKeyByBlob(hContext, hSrk, tssLen, 
					tssKeyData, &hKey)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXLKBB;
		goto tss_out;
	}

	if ((rc=Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hPolicy)) 
		!= TSS_SUCCESS) {
		tpm_errno = ETSPIGETPO;
		goto tss_out;
	}

	if ((rc=Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_PLAIN, 
					strlen(TPMSEAL_SECRET), 
					TPMSEAL_SECRET)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out;
	}

        if ((rc=Tspi_Data_Unseal(hEncdata, hKey, &symKeyLen,
               	             &symKey)) != TSS_SUCCESS) {
		tpm_errno = ETSPIDATU;
		goto tss_out;
	}

	start = BIO_tell(bdata);
	res_data = malloc(stats.st_size-start);
	if ( res_data == NULL ) {
		rc = TPMSEAL_STD_ERROR;
		tpm_errno = ENOMEM;
		goto tss_out;
	}
	res_size = 0;

	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
		tpm_errno = EAGAIN;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

        /* Decrypt */
        EVP_CIPHER_CTX ctx;
        EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), symKey, TPMSEAL_IV);

       	/* retrieve the encrypted data needed */
	bdata = BIO_push(b64, bdata);
        while ((rcLen = BIO_read(bdata, data, sizeof(data))) > 0 ) {
		datLen += rcLen;
		EVP_DecryptUpdate(&ctx, res_data+res_size, 
					&rcLen, data, rcLen);
		res_size += rcLen;
        }
	bdata = BIO_pop(b64);
        EVP_DecryptFinal(&ctx, res_data+res_size, &rcLen);
	res_size += rcLen;

	start += ((datLen * 4)+2)/3; //add base64 chars
	start += 3 - ((datLen * 4)%3); //add base64 pad
	start += ((((datLen * 4)+2)/3)+63)/64; //add base64 nl

	/* looking for Footer */
	BIO_seek(bdata, start);
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp( data, TPMSEAL_FTR_STRING, 
			strlen(TPMSEAL_FTR_STRING)) != 0 ) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = ENOTSSFTR;
		goto tss_out;
	}

tss_out:
	Tspi_Context_Close(hContext);
out:

	if ( bdata )
		BIO_free(bdata);
	if ( b64 )
		BIO_free(b64);

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
		case TPMSEAL_STD_ERROR:
			return strerror(tpm_errno);
		case TPMSEAL_FILE_ERROR:
			switch(tpm_errno) {
				case ENOTSSHDR:
					return _("No TSS header present");
				case ENOTSSFTR:
					return _("No TSS footer present");
				case EWRONGTSSTAG:
					return _("Wrong TSS tag");
				case EWRONGEVPTAG:
					return _("Wrong EVP tag");
				case EWRONGDATTAG:
					return _("Wrong DATA tag");
				case EWRONGKEYTYPE:
					return _("Not a Symmetric EVP Key");
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
