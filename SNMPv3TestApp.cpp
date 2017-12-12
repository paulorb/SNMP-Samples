// SNMPv3TestApp.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <net-snmp/net-snmp-config.h>

#define HAVE_STRING_H 1
#define HAVE_WINSOCK_H 1
#define HAVE_STDINT_H 1
#define HAVE_STRTOUL 1
#define HAVE_STRTOL 1
#define HAVE_STRDUP 1
#define RETSIGTYPE void


#ifdef VS2008
#undef HAVE_STDINT_H
typedef unsigned char uint8_t;
typedef char int8_t;
typedef unsigned __int16 uint16_t;
typedef __int16 int16_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
typedef unsigned __int64 uintmax_t;
typedef __int64 intmax_t;
#endif

typedef int16_t mode_t;

#include <net-snmp/net-snmp-includes.h>










/* change the word "define" to "undef" to try the (insecure) SNMPv1 version */
#define DEMO_USE_SNMP_VERSION_3

#ifdef DEMO_USE_SNMP_VERSION_3
const char *our_v3_passphrase = "The Net-SNMP Demo Password";
#endif

int main(int argc, char ** argv)
{
	netsnmp_session session, *ss;
	netsnmp_pdu *pdu;
	netsnmp_pdu *response;

	oid anOID[MAX_OID_LEN];
	size_t anOID_len;

	netsnmp_variable_list *vars;
	int status;
	int count = 1;

	/*
	* Initialize the SNMP library
	*/
	init_snmp("snmpdemoapp");

	debug_register_tokens("all");
	snmp_set_do_debugging(1);


	/*
	* Initialize a "session" that defines who we're going to talk to
	*/
	snmp_sess_init(&session);                   /* set up defaults */
	//192.94.214.205
	//test.net-snmp.org
	session.peername = strdup("192.94.214.205");

	/* set up the authentication parameters for talking to the server */

#ifdef DEMO_USE_SNMP_VERSION_3

	/* Use SNMPv3 to talk to the experimental server */

	/* set the SNMP version number */
	session.version = SNMP_VERSION_3;

	/* set the SNMPv3 user name */
	session.securityName = strdup("MD5User");
	session.securityNameLen = strlen(session.securityName);

	/* set the security level to authenticated, but not encrypted */
	session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;

	/* set the authentication method to MD5 */
	session.securityAuthProto = usmHMACMD5AuthProtocol;
	session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol) / sizeof(oid);
	session.securityAuthKeyLen = USM_AUTH_KU_LEN;

	/* set the authentication key to a MD5 hashed version of our
	passphrase "The Net-SNMP Demo Password" (which must be at least 8
	characters long) */
	if (generate_Ku(session.securityAuthProto,
		session.securityAuthProtoLen,
		(u_char *)our_v3_passphrase, strlen(our_v3_passphrase),
		session.securityAuthKey,
		&session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
		snmp_perror(argv[0]);
		snmp_log(LOG_ERR,
			"Error generating Ku from authentication pass phrase. \n");
		exit(1);
	}

	//Privacy
	session.securityPrivProto = usmDESPrivProtocol;
	session.securityPrivProtoLen = sizeof(usmDESPrivProtocol) / sizeof(oid);
	session.securityPrivKeyLen = USM_PRIV_KU_LEN;

	if (generate_Ku(session.securityAuthProto,
		session.securityAuthProtoLen,
		(u_char *)our_v3_passphrase, strlen(our_v3_passphrase),
		session.securityPrivKey,
		&session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
		exit(1);

	}



#else /* we'll use the insecure (but simplier) SNMPv1 */

	/* set the SNMP version number */
	session.version = SNMP_VERSION_1;

	/* set the SNMPv1 community name used for authentication */
	session.community = "demopublic";
	session.community_len = strlen(session.community);

#endif /* SNMPv1 */

	/*
	* Open the session
	*/
	SOCK_STARTUP;
//	ss = snmp_open(&session);                     /* establish the session */
	void * ssret = snmp_sess_open(&session);

	if (ssret == NULL) {
		snmp_sess_perror("ack", &session);
		SOCK_CLEANUP;
		exit(1);
	}

	/*
	* Create the PDU for the data for our request.
	*   1) We're going to GET the system.sysDescr.0 node.
	*/
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	anOID_len = MAX_OID_LEN;
	if (!snmp_parse_oid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len)) {
		snmp_perror(".1.3.6.1.2.1.1.1.0");
		SOCK_CLEANUP;
		exit(1);
	}
#if OTHER_METHODS
	/*
	*  These are alternatives to the 'snmp_parse_oid' call above,
	*    e.g. specifying the OID by name rather than numerically.
	*/
	read_objid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len);
	get_node("sysDescr.0", anOID, &anOID_len);
	read_objid("system.sysDescr.0", anOID, &anOID_len);
#endif

	snmp_add_null_var(pdu, anOID, anOID_len);

	/*
	* Send the Request out.
	*/
	//status = snmp_synch_response(ss, pdu, &response);

	status = snmp_sess_synch_response(ssret, pdu, &response);


	/*
	* Process the response.
	*/
	if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
		/*
		* SUCCESS: Print the result variables
		*/

		for (vars = response->variables; vars; vars = vars->next_variable)
			print_variable(vars->name, vars->name_length, vars);

		/* manipuate the information ourselves */
		for (vars = response->variables; vars; vars = vars->next_variable) {
			if (vars->type == ASN_OCTET_STR) {
				char *sp = (char *)malloc(1 + vars->val_len);
				memcpy(sp, vars->val.string, vars->val_len);
				sp[vars->val_len] = '\0';
				printf("value #%d is a string: %s\n", count++, sp);
				free(sp);
			}
			else
				printf("value #%d is NOT a string! Ack!\n", count++);
		}
	}
	else {
		/*
		* FAILURE: print what went wrong!
		*/

		if (status == STAT_SUCCESS)
			fprintf(stderr, "Error in packet\nReason: %s\n",
				snmp_errstring(response->errstat));
		else if (status == STAT_TIMEOUT)
			fprintf(stderr, "Timeout: No response from %s.\n",
				session.peername);
		else
			snmp_sess_perror("snmpdemoapp", ss);

	}

	/*
	* Clean up:
	*  1) free the response.
	*  2) close the session.
	*/
	if (response)
		snmp_free_pdu(response);
	snmp_close(ss);

	SOCK_CLEANUP;
	return (0);
} /* main() */