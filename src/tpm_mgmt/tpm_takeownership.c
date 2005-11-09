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

static inline TSS_RESULT tpmTakeOwnership(TSS_HTPM a_hTpm, TSS_HKEY a_hSrk)
{

	TSS_RESULT result =
	    Tspi_TPM_TakeOwnership(a_hTpm, a_hSrk, NULL_HKEY);
	tspiResult("Tspi_TPM_TakeOwnership", result);

	return result;
}

int main(int argc, char **argv)
{

	char *szTpmPasswd = NULL;
	char *szSrkPasswd = NULL;
	TSS_HCONTEXT hContext;
	TSS_HTPM hTpm;
	TSS_HKEY hSrk;
	TSS_FLAG fSrkAttrs;
	TSS_HPOLICY hTpmPolicy, hSrkPolicy;
	int iRc = -1;

        initIntlSys();

	if (genericOptHandler(argc, argv, "", NULL, 0, NULL, NULL) != 0)
		goto out;

	// Prompt for owner password
	szTpmPasswd = getPasswd(_("Enter owner password: "), TRUE);
	if (!szTpmPasswd) {
		goto out;
	}
	// Prompt for srk password
	szSrkPasswd = getPasswd(_("Enter SRK password: "), TRUE);
	if (!szSrkPasswd) {
		goto out;
	}

	if (contextCreate(&hContext) != TSS_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSS_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSS_SUCCESS)
		goto out_close;

	if (policyGet(hTpm, &hTpmPolicy) != TSS_SUCCESS)
		goto out_close;

	if (policySetSecret(hTpmPolicy, strlen(szTpmPasswd), szTpmPasswd)
	    != TSS_SUCCESS)
		goto out_close;

	fSrkAttrs = TSS_KEY_TSP_SRK;
	
	if (contextCreateObject
	    (hContext, TSS_OBJECT_TYPE_RSAKEY, fSrkAttrs,
	     &hSrk) != TSS_SUCCESS)
		goto out_close;

	if (policyGet(hSrk, &hSrkPolicy) != TSS_SUCCESS)
		goto out_obj_close;

	if (policySetSecret(hSrkPolicy, strlen(szSrkPasswd), szSrkPasswd)
		    != TSS_SUCCESS)
		goto out_obj_close;

	if (tpmTakeOwnership(hTpm, hSrk) != TSS_SUCCESS)
		goto out_obj_close;

	iRc = 0;
	logSuccess(argv[0]);

      out_obj_close:
	contextCloseObject(hContext, hSrk);

      out_close:
	contextClose(hContext);

      out:
	if (szTpmPasswd)
		shredPasswd(szTpmPasswd);

	if (szSrkPasswd)
		shredPasswd(szSrkPasswd);

	return iRc;
}
