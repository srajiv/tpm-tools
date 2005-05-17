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
#include <netinet/in.h>
#include <stdlib.h>		//for def. exit
#include "tpm_tspi.h"


int cmdVersion(const char *a_szCmd)
{
	TSS_HCONTEXT hContext;
	TSS_HTPM hTpm;
	UINT32 uiSubCap;
	BYTE *pSubCap;
	UINT32 uiResultLen;
	BYTE *pResult;
	int iRc = -1;

	if (contextCreate(&hContext) != TSS_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSS_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSS_SUCCESS)
		goto out_close;

	if (getCapability(hTpm, TSS_TPMCAP_VERSION, 0, NULL, &uiResultLen,
			  &pResult) != TSS_SUCCESS)
		goto out_close;
	logMsg(_("  TPM Version:         "));
	logHex(uiResultLen, pResult);
	logMsg("\n");

	uiSubCap = TSS_TPMCAP_PROP_MANUFACTURER;
	pSubCap = (BYTE *) & uiSubCap;
	if (getCapability(hTpm, TSS_TPMCAP_PROPERTY, sizeof(uiSubCap),
			  pSubCap, &uiResultLen, &pResult) != TSS_SUCCESS)
		goto out_close;
	logMsg(_("  Manufacturer Info:   "));
	logHex(uiResultLen, pResult);
	logMsg("\n");

	iRc = 0;
	logSuccess(a_szCmd);

      out_close:
	contextClose(hContext);

      out:
	return iRc;
}


int main(int argc, char *argv[])
{
	int rc;

        initIntlSys();

	rc = genericOptHandler(argc, argv, "", NULL, 0, NULL, NULL);
	if (rc)
		exit(0);

	rc = cmdVersion(argv[0]);

	return rc;
}
