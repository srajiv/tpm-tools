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

#include "tpm_utils.h"
#include "tpm_tspi.h"

struct changeAuth {
	char *name;
	char *prompt;
	BOOL change;
};

//Order important so you authenticate once even if both changed with one command
enum {
	srk =  0,
	owner
};

static struct changeAuth auths[] = {
		{N_("SRK"), N_("Enter new SRK password: "), FALSE},
		{N_("owner"), N_("Enter new owner password: "), FALSE},
		{NULL, NULL, FALSE },
	};
static BOOL changeRequested = FALSE;

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logUnicodeCmdOption();
	logCmdOption("-o, --owner", _("Change the owner password."));
	logCmdOption("-s, --srk", _("Change the SRK password."));
	logCmdOption("-g, --original_password_unicode", _("Use TSS UNICODE encoding for original password to comply with applications using TSS popup boxes"));
	logCmdOption("-n, --new_password_unicode", _("Use TSS UNICODE encoding for new password to comply with applications using TSS popup boxes"));
}

static BOOL origUnicode = FALSE;
static BOOL newUnicode = FALSE;

static int parse(const int aOpt, const char *aArg)
{

	switch (aOpt) {

	case 'o':
		auths[owner].change = TRUE;
		changeRequested = TRUE;
		break;
	case 's':
		auths[srk].change = TRUE;
		changeRequested = TRUE;
		break;
	case 'g':
		origUnicode = TRUE;
		break;
	case 'n':
		newUnicode = TRUE;
		break;
	default:
		return -1;
	}
	return 0;
}

static TSS_RESULT
tpmChangeAuth(TSS_HCONTEXT aObjToChange,
	      TSS_HOBJECT aParent, TSS_HPOLICY aNewPolicy)
{
	TSS_RESULT result =
	    Tspi_ChangeAuth(aObjToChange, aParent, aNewPolicy);
	tspiResult("Tspi_ChangeAuth", result);

	return result;
}

/*
 * Affect: Change owner or srk password
 * Default: No action
 * Required: Owner auth
 */
int main(int argc, char **argv)
{

	int i = 0, iRc = -1;
	char *passwd = NULL;
	int pswd_len;
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hTpmPolicy, hNewPolicy;
	TSS_HTPM hTpm;
	TSS_HTPM hSrk;
	struct option opts[] = { {"owner", no_argument, NULL, 'o'},
	{"srk", no_argument, NULL, 's'},
	{"original_password_unicode", no_argument, NULL, 'g'},
	{"new_password_unicode", no_argument, NULL, 'n'},
	};

        initIntlSys();

	if (genericOptHandler
	    (argc, argv, "sogn", opts, sizeof(opts) / sizeof(struct option),
	     parse, help) != 0)
		goto out;

	if (!changeRequested) {	//nothing selected
		help(argv[0]);
		goto out;
	}
	//Connect to TSS and TPM
	if (contextCreate(&hContext) != TSS_SUCCESS)
		goto out;

	if (contextConnect(hContext) != TSS_SUCCESS)
		goto out_close;

	if (contextGetTpm(hContext, &hTpm) != TSS_SUCCESS)
		goto out_close;

	//Prompt for owner password
	passwd = _getPasswd(_("Enter owner password: "), &pswd_len, FALSE, origUnicode || useUnicode );
	if (!passwd) {
		logError(_("Failed to get owner password\n"));
		goto out_close;
	}
	if (policyGet(hTpm, &hTpmPolicy) != TSS_SUCCESS)
		goto out_close;
	if (policySetSecret
	    (hTpmPolicy, pswd_len, (BYTE *)passwd) != TSS_SUCCESS)
		goto out_close;

	shredPasswd(passwd);
	passwd = NULL;

	do {
		if (auths[i].change) {
			logInfo(_("Changing password for: %s.\n"), _(auths[i].name));
			passwd = _getPasswd(_(auths[i].prompt), &pswd_len, TRUE, newUnicode || useUnicode );
			if (!passwd) {
				logError(_("Failed to get new password.\n"));
				goto out_close;
			}

			if (contextCreateObject
			    (hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
			     &hNewPolicy) != TSS_SUCCESS)
				goto out_close;

			if (policySetSecret
			    (hNewPolicy, pswd_len,
			     (BYTE *)passwd) != TSS_SUCCESS)
				goto out_close;

			if (i == owner) {
				if (tpmChangeAuth
				    (hTpm, NULL_HOBJECT, hNewPolicy)
				    != TSS_SUCCESS)
					goto out_close;
			} else if (i == srk) {
				if (keyLoadKeyByUUID
				    (hContext, TSS_PS_TYPE_SYSTEM,
				     SRK_UUID, &hSrk) != TSS_SUCCESS)
					goto out_close;
				if (tpmChangeAuth
				    (hSrk, hTpm,
				     hNewPolicy) != TSS_SUCCESS)
					goto out_close;
			}
			logInfo(_("Change of %s password successful.\n"),
			       _(auths[i].name));
			shredPasswd(passwd);
			passwd = NULL;
		}
	}
	while (auths[++i].name);

	iRc = 0;


      out_close:
	contextClose(hContext);
      out:
	if (passwd)
		shredPasswd(passwd);
	return iRc;
}
