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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "tpm_tspi.h"
#include "tpm_utils.h"
#include <openssl/evp.h>

static inline TSS_RESULT keyCreateKey(TSS_HKEY a_hKey, TSS_HKEY a_hWrapKey, TSS_HPCRS a_hPcrs )
{
	TSS_RESULT result = 
		Tspi_Key_CreateKey(a_hKey, a_hWrapKey, a_hPcrs);
	tspiResult("Tspi_Key_CreateKey", result);
	return result;
}

static inline TSS_RESULT dataSeal(TSS_HENCDATA a_hEncdata, TSS_HKEY a_hKey, UINT32 a_len, BYTE* a_data)
{

	TSS_RESULT result =
	    Tspi_Data_Seal(a_hEncdata, a_hKey, a_len, a_data, NULL_HPCRS);
	tspiResult("Tspi_Data_Seal", result);

	return result;
}

static void help(const char *aCmd) 
{
	logCmdHelp(aCmd);
	logCmdOption("-f, --filename", _("Filename containing key to seal"));
	logCmdOption("-0, --output", _("Filename to write sealed key to.  Default is the same as the input file"));

}

#define MAX_FILENAME_SIZE 256
#define PEM_STRING_RSA "RSA PRIVATE KEY"
#define PEM_STRING_DSA "DSA PRIVATE KEY"
#define DER_STRING "PRIVATE KEY"
#define TSS_STRING "TSS"
#define BEGIN_STRING "-----BEGIN "
#define END_STRING "-----END "
#define DASH_STRING "-----"
#define RSA_HEADER "BEGIN RSA PRIVATE KEY"
#define DSA_HEADER "BEGIN DSA PRIVATE KEY"
#define TSS_HEADER "BEGIN TSS"

#define POLICY_SECRET "password"

static char in_filename[MAX_FILENAME_SIZE] = "", out_filename[MAX_FILENAME_SIZE]="";
static const char iv[8] = "IBM SEAL";
static int parse(const int aOpt, const char* aArg) 
{
	int rc = -1;
	switch(aOpt) {
		case 'f':
			if ( aArg ) {
				strncpy(in_filename, aArg, MAX_FILENAME_SIZE);
				rc = 0;
			}
		case 'o':
			if( aArg ) {
				strncpy(out_filename, aArg, MAX_FILENAME_SIZE);
				rc = 0;
			}
	}
	return rc;

}

int main(int argc, char **argv)
{

	TSS_HCONTEXT hContext;
	TSS_HTPM hTpm;
	TSS_HKEY hSrk, hKey;
	TSS_HENCDATA hEncdata;
	TSS_HPOLICY hPolicy;
	int iRc = -1;
	struct option opts[] = { {"filename", required_argument, NULL, 'f'},
				{ "output", required_argument, NULL, 'o'} };
	FILE *file;
	struct stat stat_buf;
	int fd, len, i;
	char id_string[sizeof(PEM_STRING_RSA)];
	char line[66];
	char *data = NULL;
	char *encData = NULL;
	int encDataLen;
	UINT32 encLen;
	BYTE* encKey;
	BYTE* randKey;
	UINT32 sealKeyLen;
	BYTE* sealKey;
	TSS_FLAG keyFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048  |
				TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
				TSS_KEY_NOT_MIGRATABLE;
        initIntlSys();

	if (genericOptHandler(argc, argv, "fo", opts, sizeof(opts)/sizeof(struct option), parse, help) != 0) {
		logError(_("Invalid option\n"));
		goto out;
	}

	if (strlen( out_filename ) == 0 )
		strncpy( out_filename, in_filename, MAX_FILENAME_SIZE);

	if( (file = fopen( in_filename, "r")) < 0) {
		logError(_("Unable to open input file: %s\n"), in_filename);
		goto out;
	}

	if ( stat(in_filename, &stat_buf) != 0 ) {
		logError(_("Unable to stat input file: %s\n"), in_filename);
		goto out_close_file;
	}

	if ( !fgets(line, sizeof(line), file) ) {
		logError(_("Unable to retrieve header.\n"));
		goto out_close_file;
	}

	if ( strstr(line, RSA_HEADER) ) 
		strcpy(id_string, PEM_STRING_RSA);
	else if ( strstr(line, DSA_HEADER) )
		strcpy(id_string, PEM_STRING_DSA);
	else if ( !strstr(line, TSS_HEADER) ) /* assume DER b/c DER has no header */
		strcpy(id_string, DER_STRING);
	else {
		logError(_("Invalid header\n"));
		goto out_close_file;
	}



	data = malloc( stat_buf.st_size );
	encData = malloc( stat_buf.st_size + EVP_CIPHER_block_size(EVP_desx_cbc()));
	if ( !data || ! encData ) {
		logError(_("Out of memory\n"));
		goto out_close_file;
	}
	
	fseek(file, 0, SEEK_SET);
	if ( (len = fread( data, 1, stat_buf.st_size, file)) < 0 ) {
		logError(_("Unable to read data.\n"));
		goto out_close_file;
	}

	if (contextCreate(&hContext) != TSS_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSS_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSS_SUCCESS)
		goto out_close;

	if (tpmGetRandom(hTpm, EVP_CIPHER_key_length(EVP_desx_cbc()), 
			&randKey) != TSS_SUCCESS)
		goto out_close;

	EVP_CIPHER_CTX ctx;
	int tmpLen;
	EVP_EncryptInit(&ctx, EVP_des_cbc(), randKey, iv);
	EVP_EncryptUpdate(&ctx, encData, &tmpLen, data, len);
	encDataLen = tmpLen;
	EVP_EncryptFinal(&ctx, encData+encDataLen, &tmpLen);
	encDataLen += tmpLen;

	if (keyLoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,SRK_UUID,&hSrk) != TSS_SUCCESS)
		goto out_close;

	if (contextCreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, keyFlags, &hKey) != TSS_SUCCESS)
		goto out_close;

	if (policyGet(hKey, &hPolicy) != TSS_SUCCESS)
		goto out_close;
	
	if (policySetSecret(hPolicy, strlen(POLICY_SECRET), POLICY_SECRET) != TSS_SUCCESS)
		goto out_close;

	if(keyCreateKey(hKey, hSrk, NULL_HPCRS) != TSS_SUCCESS)
		goto out_close;

	if (keyLoadKey(hKey, hSrk) != TSS_SUCCESS)
		goto out_close;	

	if (contextCreateObject
	    (hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL,
	     &hEncdata) != TSS_SUCCESS)
		goto out_close;

	if (policyGet(hEncdata, &hPolicy) != TSS_SUCCESS)
		goto out_close;
	
	if (policySetSecret(hPolicy, strlen(POLICY_SECRET), POLICY_SECRET) != TSS_SUCCESS)
		goto out_close;

	if (dataSeal(hEncdata, hKey, 24, randKey) != TSS_SUCCESS)
		goto out_close;	

	if (getAttribData(hEncdata, TSS_TSPATTRIB_ENCDATA_BLOB,
 			  TSS_TSPATTRIB_ENCDATABLOB_BLOB, &encLen, 
			  &encKey) != TSS_SUCCESS)
		goto out_close;

	if (getAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &sealKeyLen, &sealKey) != TSS_SUCCESS)
		goto out_close;

	file = fopen(out_filename, "w+");
	if (!file) {
		logError(_("Unable to open output file: %s\n"), out_filename);
		goto out_stream_close;
	}
	
	fprintf(file, "%s%s %s%s\n", BEGIN_STRING, TSS_STRING, id_string, DASH_STRING);
	fprintf(file, "-----TSS KEY-----\n");
	for(i=0; i<sealKeyLen; i++) {
		fprintf( file, "%02x", 0xFF & sealKey[i]);
		if ( ! ((i+1) %32 ))
			fprintf(file, "\n");
	}
	fprintf(file, "\n");
	fprintf(file, "-----ENC KEY-----\n");
	for(i=0; i< encLen; i++) {
		fprintf( file, "%02x", 0xFF & encKey[i]);
		if (! ((i+1) % 32 ))
			fprintf(file, "\n");
	}
	fprintf(file, "\n");
	fprintf(file, "-----SSL KEY-----\n");
	for(i=0; i<encDataLen; i++) {
		fprintf(file, "%02x", 0xFF & encData[i]);
		if (! ((i+1) % 32 ))
			fprintf(file, "\n");
	}	
	fprintf(file, "\n");
	fprintf(file, "%s%s %s%s\n", END_STRING, TSS_STRING, id_string, DASH_STRING);
	
	iRc = 0;
	logSuccess(argv[0]);

	out_stream_close:
		fclose(file);

      out_obj_close:
	contextCloseObject(hContext, hSrk);

      out_close:
	contextClose(hContext);

     out_close_file:	
	close(fd);

      out:
	if ( data )
		free( data );
	if ( encData )
		free( encData );
	return iRc;
}
