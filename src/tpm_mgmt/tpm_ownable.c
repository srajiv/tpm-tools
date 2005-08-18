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

/* 
 * Affect: Change the TPM state regarding if take_ownership can be performed.
 * Default: Set state to ownable
 * Requires: Physical presence
 */

//Controlled by option inputs
static TSS_BOOL bValue = TRUE;
static BOOL bCheck = FALSE;
static BOOL changeRequested = FALSE;

static int parse(const int aOpt, const char *aArg)
{

	switch (aOpt) {
	case 's':
		logDebug(_("Changing mode to check status.\n"));
		bCheck = TRUE;
		break;
	case 'p':
		logDebug(_("Changing to prevent ownership mode\n"));
		bValue = FALSE;
		changeRequested = TRUE;
		break;
	case 'a':
		logDebug(_("Changing to allow ownership mode\n"));
		bValue = TRUE;
		changeRequested = TRUE;
		break;
	default:
		return -1;
	}
	return 0;
}

static void help(const char *aCmd)
{

	logCmdHelp(aCmd);
	logCmdOption("-s, --status", _("Display current status"));
	logCmdOption("-a, --allow", _("Allow TPM takeownership command"));
	logCmdOption("-p, --prevent", _("Prevent TPM takeownership command"));
}

int main(int argc, char **argv)
{

	char *szTpmPasswd = NULL;
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hTpmPolicy;
	TSS_HTPM hTpm;
	int iRc = -1;
	struct option opts[] = { {"allow", no_argument, NULL, 'a'},
	{"prevent", no_argument, NULL, 'p'},
	{"status", no_argument, NULL, 's'},
	};

        initIntlSys();

	if (genericOptHandler
	    (argc, argv, "aps", opts, sizeof(opts) / sizeof(struct option),
	     parse, help) != 0)
		goto out;

	if (contextCreate(&hContext) != TSS_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSS_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSS_SUCCESS)
		goto out_close;

	if (bCheck || !changeRequested) {
		szTpmPasswd = getPasswd(_("Enter owner password: "), FALSE);
		if (!szTpmPasswd) {
			logMsg(_("Failed to get password\n"));
			goto out_close;
		}
		if (policyGet(hTpm, &hTpmPolicy) != TSS_SUCCESS)
			goto out_close;

		if (policySetSecret
		    (hTpmPolicy, strlen(szTpmPasswd),
		     szTpmPasswd) != TSS_SUCCESS)
			goto out_close;
		if (tpmGetStatus
		    (hTpm, TSS_TPMSTATUS_SETOWNERINSTALL,
		     &bValue) != TSS_SUCCESS)
			goto out_close;

		logMsg(_("Ownable status: %s\n"), logBool(mapTssBool(bValue)));
		goto out_success;
	}

	if (tpmSetStatus(hTpm, TSS_TPMSTATUS_SETOWNERINSTALL, bValue) !=
	    TSS_SUCCESS)
		goto out_close;

      out_success:
	iRc = 0;
	logSuccess(argv[0]);

      out_close:
	contextClose(hContext);

      out:
	if (szTpmPasswd)
		shredPasswd(szTpmPasswd);
	return iRc;
}
