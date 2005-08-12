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
#include <openssl/evp.h>
#include <limits.h>
#include "tpm_tspi.h"
#include "tpm_utils.h"
#include "tpm_seal.h"

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logCmdOption("-i, --infile FILE",
		     _
		     ("Filename containing key to seal. Default is STDIN."));
	logCmdOption("-o, --outfile FILE",
		     _
		     ("Filename to write sealed key to.  Default is STDOUT."));
	logCmdOption("-p, --pcr NUMBER",
		     _
		     ("PCR to seal data to.  Default is none.  This option can be specified multiple times to choose more than one PCR."));

}

static char in_filename[PATH_MAX] = "", out_filename[PATH_MAX] = "";
static TSS_HPCRS hPcrs = NULL_HPCRS;
static TSS_HCONTEXT hContext;
static TSS_HTPM hTpm;

static int parse(const int aOpt, const char *aArg)
{
	int rc = -1;
	UINT32 pcr_idx;
	BYTE *pcr_idx_val;
	UINT32 pcr_siz;

	switch (aOpt) {
	case 'i':
		if (aArg) {
			strncpy(in_filename, aArg, PATH_MAX);
			rc = 0;
		}
		break;
	case 'o':
		if (aArg) {
			strncpy(out_filename, aArg, PATH_MAX);
			rc = 0;
		}
		break;
	case 'p':
		if (aArg) {
			if (hPcrs == NULL_HPCRS) {
				if (Tspi_Context_CreateObject(hContext,
							      TSS_OBJECT_TYPE_PCRS,
							      0,
							      &hPcrs) !=
				    TSS_SUCCESS)
					break;
			}
			pcr_idx = atoi(aArg);
			if (Tspi_TPM_PcrRead(hTpm, pcr_idx, &pcr_siz,
					     &pcr_idx_val) != TSS_SUCCESS)
				break;

			if (Tspi_PcrComposite_SetPcrValue(hPcrs, pcr_idx,
							  pcr_siz,
							  pcr_idx_val)
			    != TSS_SUCCESS)
				break;

			rc = 0;
		}
		break;
	}
	return rc;

}

int main(int argc, char **argv)
{

	TSS_HKEY hSrk, hKey;
	TSS_HENCDATA hEncdata;
	TSS_HPOLICY hPolicy;
	int iRc = -1;
	struct option opts[] =
	    { {"infile", required_argument, NULL, 'i'},
	{"outfile", required_argument, NULL, 'o'},
	{"pcr", required_argument, NULL, 'p'}
	};
	FILE *ifile = NULL, *ofile = NULL;
	int len = 0, i;
	unsigned char line[66];		/* 64 data \n \0 */
	unsigned char encData[64];
	int encDataLen;
	UINT32 encLen;
	BYTE *encKey;
	BYTE *randKey = NULL;
	UINT32 sealKeyLen;
	BYTE *sealKey;
	TSS_FLAG keyFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
	    TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
	    TSS_KEY_NOT_MIGRATABLE;

	initIntlSys();

	if (contextCreate(&hContext) != TSS_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSS_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSS_SUCCESS)
		goto out_close;

	if (genericOptHandler(argc, argv, "i:o:p:", opts,
			      sizeof(opts) / sizeof(struct option), parse,
			      help) != 0) {
		logError(_("Invalid option\n"));
		goto out_close;
	}

	if (strlen(in_filename) == 0)
		ifile = stdin;
	else if ((ifile = fopen(in_filename, "r")) < 0) {
		logError(_("Unable to open input file: %s\n"),
			 in_filename);
		goto out_close;
	}

	if (!fgets(line, sizeof(line), ifile)) {
		logError(_("Unable to retrieve header.\n"));
		goto out_stream_close;
	}

	if ( strcmp(line, TPMSEAL_HDR_STRING) == 0 ) {
		logError(_("Invalid header: file already sealed\n"));
		goto out_stream_close;
	}

	if (tpmGetRandom(hTpm, EVP_CIPHER_key_length(EVP_aes_256_cbc()),
			 &randKey) != TSS_SUCCESS)
		goto out_stream_close;

	if (keyLoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSrk)
	    != TSS_SUCCESS)
		goto out_stream_close;

	if (contextCreateObject
	    (hContext, TSS_OBJECT_TYPE_RSAKEY, keyFlags,
	     &hKey) != TSS_SUCCESS)
		goto out_stream_close;

	if (policyGet(hKey, &hPolicy) != TSS_SUCCESS)
		goto out_stream_close;

	if (policySetSecret(hPolicy, strlen(TPMSEAL_SECRET), TPMSEAL_SECRET)
	    != TSS_SUCCESS)
		goto out_stream_close;

	if (keyCreateKey(hKey, hSrk, NULL_HPCRS) != TSS_SUCCESS)
		goto out_stream_close;

	if (keyLoadKey(hKey, hSrk) != TSS_SUCCESS)
		goto out_stream_close;

	if (contextCreateObject
	    (hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL,
	     &hEncdata) != TSS_SUCCESS)
		goto out_stream_close;

	if (policyGet(hEncdata, &hPolicy) != TSS_SUCCESS)
		goto out_stream_close;

	if (policySetSecret(hPolicy, strlen(TPMSEAL_SECRET), TPMSEAL_SECRET)
	    != TSS_SUCCESS)
		goto out_stream_close;

	if (dataSeal
	    (hEncdata, hKey, EVP_CIPHER_key_length(EVP_aes_256_cbc()),
	     randKey, hPcrs) != TSS_SUCCESS)
		goto out_stream_close;

	if (getAttribData(hEncdata, TSS_TSPATTRIB_ENCDATA_BLOB,
			  TSS_TSPATTRIB_ENCDATABLOB_BLOB, &encLen,
			  &encKey) != TSS_SUCCESS)
		goto out_stream_close;

	if (getAttribData
	    (hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
	     &sealKeyLen, &sealKey) != TSS_SUCCESS)
		goto out_stream_close;

	if (strlen(out_filename) == 0)
		ofile = stdout;
	else if (!(ofile = fopen(out_filename, "w+"))) {
		logError(_("Unable to open output file: %s\n"),
			 out_filename);
		goto out_stream_close;
	}

	fprintf(ofile, "%s\n", TPMSEAL_HDR_STRING);
	fprintf(ofile, "%s\n", TPMSEAL_TSS_STRING); 
	for (i = 0; i < sealKeyLen; i++) {
		fprintf(ofile, "%02x", 0xFF & sealKey[i]);
		if (!((i + 1) % 32))
			fprintf(ofile, "\n");
	}
	fprintf(ofile, "\n");
	fprintf(ofile, "%s\n", TPMSEAL_EVP_STRING);
	fprintf(ofile, "%s: %s\n", TPMSEAL_KEYTYPE_SYM, TPMSEAL_CIPHER_AES256CBC);
	for (i = 0; i < encLen; i++) {
		fprintf(ofile, "%02x", 0xFF & encKey[i]);
		if (!((i + 1) % 32))
			fprintf(ofile, "\n");
	}
	fprintf(ofile, "\n");
	fprintf(ofile, "%s\n", TPMSEAL_ENC_STRING); 

	EVP_CIPHER_CTX ctx;
	EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), randKey, TPMSEAL_IV);

	do {
		EVP_EncryptUpdate(&ctx, encData, &encDataLen,
				  line, strlen(line));
		for (i = 0; i < encDataLen; i++, len++) {
			fprintf(ofile, "%02x", 0xFF & encData[i]);
			if (!((len + 1) % 32))
				fprintf(ofile, "\n");
		}
	} while (fread(line, 1, sizeof(line), ifile) > 0);

	EVP_EncryptFinal(&ctx, encData, &encDataLen);
	for (i = 0; i < encDataLen; i++, len++) {
		fprintf(ofile, "%02x", 0xFF & encData[i]);
		if (!((len + 1) % 32))
			fprintf(ofile, "\n");
	}
	if (len % 32)
		fprintf(ofile, "\n");

	fprintf(ofile, "%s\n", TPMSEAL_FTR_STRING);

	iRc = 0;
	logSuccess(argv[0]);

      out_stream_close:
	if (ifile && ifile != stdout)
		fclose(ifile);

	if (ofile && ofile != stdout)
		fclose(ofile);

      out_close:
	contextClose(hContext);

      out:
	return iRc;
}
