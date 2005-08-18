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

int main(int argc, char **argv)
{

	char *szTpmPasswd = NULL;
	TSS_RESULT tResult;
	TSS_HCONTEXT hContext;
	TSS_HTPM hTpm;
	TSS_HKEY hEk;
	TSS_HPOLICY hTpmPolicy;
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

	tResult = tpmGetPubEk(hTpm, FALSE, NULL, &hEk);
	if (tResult == TCPA_E_DISABLED_CMD) {
		logInfo
		    (_("Public PubEk access blocked, owner password required\n"));
		// Prompt for owner password
		szTpmPasswd = getPasswd(_("Enter owner password: "), FALSE);
		if (!szTpmPasswd)
			goto out_close;

		if (policyGet(hTpm, &hTpmPolicy) != TSS_SUCCESS)
			goto out_close;

		if (policySetSecret
		    (hTpmPolicy, strlen(szTpmPasswd),
		     szTpmPasswd) != TSS_SUCCESS)
			goto out_close;

		tResult = tpmGetPubEk(hTpm, TRUE, NULL, &hEk);
	}
	if (tResult != TSS_SUCCESS)
		goto out_close;

	logMsg(_("Public Endorsement Key:\n"));
	if (displayKey(hEk) != TSS_SUCCESS)
		goto out_close;

	iRc = 0;
	logSuccess(argv[0]);

      out_close:
	contextClose(hContext);

      out:
	if (szTpmPasswd)
		shredPasswd(szTpmPasswd);

	return iRc;
}
