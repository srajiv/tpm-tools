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
#include "tpm_utils.h"

static inline TSS_RESULT tpmCreateEk(TSS_HTPM a_hTpm, TSS_HKEY a_hKey,
	    TSS_VALIDATION * a_pValData)
{

	TSS_RESULT result = Tspi_TPM_CreateEndorsementKey(a_hTpm, a_hKey,
							  a_pValData);
	tspiResult("Tspi_TPM_CreateEndorsementKey", result);
	return result;
}

int main(int argc, char **argv)
{
	TSS_RESULT tResult;
	TSS_HCONTEXT hContext;
	TSS_HTPM hTpm;
	TSS_HKEY hEk;
	TSS_FLAG fEkAttrs;
	int iRc = -1;

        initIntlSys();

	if (genericOptHandler(argc, argv, NULL, NULL, 0, NULL, NULL) != 0)
		goto out;

	if (contextCreate(&hContext) != TSS_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSS_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSS_SUCCESS)
		goto out_close;

	//Initialize EK attributes here
	fEkAttrs = TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_LEGACY;
	if (contextCreateObject
		(hContext, TSS_OBJECT_TYPE_RSAKEY, fEkAttrs,
		&hEk) != TSS_SUCCESS)
		goto out_close;

	tResult = tpmCreateEk(hTpm, hEk, NULL);
	if(tResult != TSS_SUCCESS)
		goto out_close;

	iRc = 0;
	logSuccess(argv[0]);

      out_close:
	contextClose(hContext);

      out:
	return iRc;
}
