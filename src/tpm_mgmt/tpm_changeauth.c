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
	BOOL change;
};

//Order important so you authenticate once even if both changed with one command
enum {
	srk =  0,
	owner
};

static struct changeAuth auths[] = { {N_("SRK")}, {N_("owner")}, {0, 0} };
static BOOL changeRequested = FALSE;

static void help(const char *aCmd)
{
	logCmdHelp(aCmd);
	logCmdOption("-o, --owner", _("Change the owner password."));
	logCmdOption("-s, --srk", _("Change the SRK password."));
}

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
	TSS_HCONTEXT hContext;
	TSS_HPOLICY hTpmPolicy, hNewPolicy;
	TSS_HTPM hTpm;
	TSS_HTPM hSrk;
	struct option opts[] = { {"owner", no_argument, NULL, 'o'},
	{"srk", no_argument, NULL, 's'}
	};

        initIntlSys();

	if (genericOptHandler
	    (argc, argv, "so", opts, sizeof(opts) / sizeof(struct option),
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
	passwd = getPasswd(_("Enter owner password: "), FALSE);
	if (!passwd) {
		logError(_("Failed to get owner password\n"));
		goto out_close;
	}
	if (policyGet(hTpm, &hTpmPolicy) != TSS_SUCCESS)
		goto out_close;
	if (policySetSecret
	    (hTpmPolicy, strlen(passwd), passwd) != TSS_SUCCESS)
		goto out_close;

	shredPasswd(passwd);
	passwd = NULL;

	do {
		if (auths[i].change) {
			logInfo(_("Changing password for: %s.\n"), _(auths[i].name));
			const int len =
			    strlen(_("Enter new password for: ")) +
			    strlen(_(auths[i].name)) + 1;
			char prompt[len];
			snprintf(prompt, len, "%s%s",
				_("Enter new password for: "), _(auths[i].name));
			passwd = getPasswd(prompt, TRUE);
			if (!passwd) {
				logError(_("Failed to get new password.\n"));
				goto out_close;
			}

			if (contextCreateObject
			    (hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
			     &hNewPolicy) != TSS_SUCCESS)
				goto out_close;

			if (policySetSecret
			    (hNewPolicy, strlen(passwd),
			     passwd) != TSS_SUCCESS)
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
			logMsg(_("Change to %s successful.\n"),
			       _(auths[i].name));
			shredPasswd(passwd);
			passwd = NULL;
		}
	}
	while (auths[++i].name);


      out_close:
	contextClose(hContext);
      out:
	if (passwd)
		shredPasswd(passwd);
	return iRc;
}
