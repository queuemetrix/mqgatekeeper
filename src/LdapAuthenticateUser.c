//=======================================================================
// MQSeries LDAP Security Channel Exit support
// Name: LdapAuthenticateUser.c
// Requires OpenLDAP, OpenSSL
// 
// Copyright 2014 Queuemetrix Pty Ltd Australia
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//=======================================================================

//=======================================================================
//  Includes                                          
//=======================================================================
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <cmqc.h>
#include <cmqxc.h>
#include <ldap.h>
#include <libMQAuthLdap.h>

// Prototypes                             
BOOL LdapAuthenticateUser(char *ldap_user, char *ldap_pw, pLDAP_PROPERTIES  pLdapProperties); // Authenticate the user against LDAP
void WriteLogFile( pLDAP_PROPERTIES  pLdapProperties, int msgid, unsigned char msgtype, char *msgtxt,...);
void MakeCString( char *bf, char *zt, int len );

// Authenticate the user against LDAP
BOOL LdapAuthenticateUser(char *ldap_user, char *ldap_pw, pLDAP_PROPERTIES  pLdapProperties)
{

  // Just return TRUE if we don't need to authenticate
  if (!strncmp (pLdapProperties->AuthenticateUser, "FALSE",5))
  {
    WriteLogFile( pLdapProperties,709, 'D', "AuthenticateUser is set to %s\n", pLdapProperties->AuthenticateUser);
    return TRUE;
  }
  
  LDAP *ldap = NULL;
  LDAPMessage *answer = NULL;
  LDAPMessage *entry = NULL;
  char ldap_dn[256];
  int  ldap_debug     = 4;
  int  result = 0;
  int  initialise = 0;
  char filter[4096];
  
  int		  LdapAuthMethod = LDAP_AUTH_SIMPLE;
  int		  LdapVersion = LDAP_VERSION3;
  int		  LdapScope = LDAP_SCOPE_SUBTREE;
  
  // Build user DN
  strcpy(ldap_dn, pLdapProperties->LdapPrincipalPrefix);
  strcat(ldap_dn, ldap_user);
  strcat(ldap_dn, pLdapProperties->LdapPrincipalSuffix);
  WriteLogFile( pLdapProperties,930, 'D', "ldap_dn = %s, password = ...\n",ldap_dn);
  WriteLogFile( pLdapProperties,940, 'D', "Connecting to LDAP URL %s ...\n", pLdapProperties->LdapServerUrl );
  
  // Use the LDAP_OPT_PROTOCOL_VERSION session preference to specify that the client is an LDAPv3 client
  
  //result = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, LDAP_VERSION3);
  result = ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &pLdapProperties->LdapVersion);
  if ( result != LDAP_OPT_SUCCESS ) {
      WriteLogFile( pLdapProperties,951, 'E', "ERROR: ldap_set_option LDAP_OPT_PROTOCOL_VERSION failed!, %s", ldap_err2string(result));
      //ldap_perror(ldap, "ldap_set_option LDAP_OPT_PROTOCOL_VERSION failed!");
      exit(FALSE);
  } else {
    WriteLogFile( pLdapProperties,950, 'D', "Set LDAP_OPT_PROTOCOL_VERSION = LDAP_VERSION%i\n", pLdapProperties->LdapVersion);
  }
  
  // If a CA cert dir is set then use it
  if (strlen(pLdapProperties->TLS_CACertDir) > 1 )
  {
    result = ldap_set_option(ldap, LDAP_OPT_X_TLS_CACERTDIR, &pLdapProperties->TLS_CACertDir);
    if ( result != LDAP_OPT_SUCCESS ) {
        WriteLogFile( pLdapProperties,961, 'E', "ERROR: ldap_set_option LDAP_OPT_X_TLS_CACERTDIR failed!, %s", ldap_err2string(result));
        //ldap_perror(ldap, "ldap_set_option LDAP_OPT_X_TLS_CACERTDIR failed!");
        exit(FALSE);
    } else {
      WriteLogFile( pLdapProperties,960, 'D', "Set LDAP_OPT_X_TLS_CACERTDIR = %s\n", pLdapProperties->TLS_CACertDir);
    }
  }
  
  result = ldap_set_option(ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &pLdapProperties->TLS_RequireCert);
  if ( result != LDAP_OPT_SUCCESS ) {
      WriteLogFile( pLdapProperties,971, 'E', "ERROR: ldap_set_option LDAP_OPT_X_TLS_REQUIRE_CERT failed!, %s", ldap_err2string(result));
      //ldap_perror(ldap, "ldap_set_option LDAP_OPT_X_TLS_REQUIRE_CERT failed!");
      exit(FALSE);
  } else {
    WriteLogFile( pLdapProperties,970, 'D', "Set LDAP_OPT_X_TLS_REQUIRE_CERT = %s\n",pLdapProperties->TLS_RequireCertString);
  }
  
  if (strlen(pLdapProperties->TLS_CACertFile) > 1 )
  {
    result = ldap_set_option(ldap, LDAP_OPT_X_TLS_CACERTFILE, &pLdapProperties->TLS_CACertFile);
    if ( result != LDAP_OPT_SUCCESS ) {
        WriteLogFile( pLdapProperties,981, 'E', "ERROR: ldap_set_option LDAP_OPT_X_TLS_CACERTFILE failed!, %s", ldap_err2string(result));
        //ldap_perror(ldap, "ldap_set_option LDAP_OPT_X_TLS_CACERTFILE failed!");
        exit(FALSE);
    } else {
      WriteLogFile( pLdapProperties,980, 'D', "Set LDAP_OPT_X_TLS_CACERTFILE = %s\n",pLdapProperties->TLS_CACertFile);
    }
  }
  
  /* Set the debug level */
  result = ldap_set_option(ldap, LDAP_OPT_DEBUG_LEVEL, &ldap_debug);
  if ( result != LDAP_OPT_SUCCESS ) {
      WriteLogFile( pLdapProperties,991, 'E', "ERROR: ldap_set_option LDAP_OPT_DEBUG_LEVEL failed!, %s", ldap_err2string(result));
      //ldap_perror(ldap, "ldap_set_option LDAP_OPT_DEBUG_LEVEL failed!");
      return(FALSE);
  } else {
    WriteLogFile( pLdapProperties,990, 'D', "Set LDAP_OPT_DEBUG_LEVEL = %i\n", ldap_debug);
  }
  
  /* Set the Search timeout in sec */
  result = ldap_set_option(ldap, LDAP_OPT_TIMELIMIT, &pLdapProperties->SearchTimeout);
  if ( result != LDAP_OPT_SUCCESS ) {
      WriteLogFile( pLdapProperties,1001, 'E', "ERROR: ldap_set_option LDAP_OPT_TIMELIMIT failed!, %s", ldap_err2string(result));
      //ldap_perror(ldap, "ldap_set_option LDAP_OPT_TIMELIMIT failed!");
      return(FALSE);
  } else {
    WriteLogFile( pLdapProperties,1000, 'D', "Set LDAP_OPT_TIMELIMIT = %i\n",pLdapProperties->SearchTimeout);
  }
  
  /* Set the Network timeout in sec */
  result = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &pLdapProperties->LdapNetworkTimeout);
  if ( result != LDAP_OPT_SUCCESS ) {
      WriteLogFile( pLdapProperties,1003, 'E', "ERROR: ldap_set_option LDAP_OPT_NETWORK_TIMEOUT failed!, %s", ldap_err2string(result));
      //ldap_perror(ldap, "ldap_set_option LDAP_OPT_NETWORK_TIMEOUT failed!");
      return(FALSE);
  } else {
    WriteLogFile( pLdapProperties,1002, 'D', "Set LDAP_OPT_NETWORK_TIMEOUT = %i\n",pLdapProperties->LdapNetworkTimeout);
  }
  
  /* Set the follow Search Referal option  */
  if (!strncmp (pLdapProperties->LdapReferalOptString, "LDAP_OPT_OFF",12))
  {  	
  	result = ldap_set_option(ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
  	WriteLogFile( pLdapProperties,1010, 'D', "Set opt LDAP_OPT_REFERRALS = LDAP_OPT_OFF\n");
  }
  else if (!strncmp (pLdapProperties->LdapReferalOptString, "LDAP_OPT_ON",11))
  {
  	result = ldap_set_option(ldap, LDAP_OPT_REFERRALS, LDAP_OPT_ON);
  	WriteLogFile( pLdapProperties,1010, 'D', "Set opt LDAP_OPT_REFERRALS = LDAP_OPT_ON\n");
  }
  if ( result != LDAP_OPT_SUCCESS ) {
      WriteLogFile( pLdapProperties,1011, 'E', "ERROR: ldap_set_option LDAP_OPT_REFERRALS failed!, %s", ldap_err2string(result));
      //ldap_perror(ldap, "ldap_set_option LDAP_OPT_REFERRALS failed!");
      return(FALSE);
  } else {
    WriteLogFile( pLdapProperties,1010, 'D', "Set LDAP_OPT_REFERRALS = %s\n",pLdapProperties->LdapReferalOptString);
  }
  
  // Get a handle to an LDAP connection and set session preferences. 
  initialise = ldap_initialize(&ldap, pLdapProperties->LdapServerUrl);
  if (  initialise != LDAP_SUCCESS ){
    WriteLogFile( pLdapProperties,1021, 'E', "ERROR: ldap_initialize failed, %s\n", ldap_err2string(result));
    return(FALSE);
  } else {
    WriteLogFile( pLdapProperties,1020, 'D', "LDAP handle initialised\n");
  }
  
  // Bind to the server. 
  // If no DN or credentials are specified, the client binds anonymously to the server 
  result = ldap_simple_bind_s(ldap, ldap_dn, ldap_pw );
  //result = ldap_simple_bind(ldap, ldap_dn, ldap_pw );

  if ( result != LDAP_SUCCESS ) {
    WriteLogFile( pLdapProperties,1031, 'E', "ERROR: User authentication (ldap_simple_bind_s) failed: %s\n", ldap_err2string(result));
    //fprintf(stderr, "ldap_simple_bind_s: %s\n", ldap_err2string(result));
    return(FALSE);
  } else {
    WriteLogFile( pLdapProperties,1030, 'D', "SUCCESS: LDAP connection successful.\n");
  }
  
  // Build the search filter string to check for group 
  // The attribute list to be returned in a search, use NULL for getting all attributes
  char *attrs[]       = {"displayName", "memberOf", NULL};
     
  // Specify if the search should return only attribute types (1), or both type and value (0)
  int  attrsonly      = 0;
  int  entries_found  = 0;
  char *dn            = "";
  char *attribute     = "";
  int  i              = 0;
  char **values;
  
  if (strlen(pLdapProperties->LdapGroupSearchFilter) > 1 )
  {

    snprintf(filter, sizeof(filter), "(&(%s)(%s=%s)%s)","objectClass=user", pLdapProperties->LdapUserSearchAttribute, ldap_user, pLdapProperties->LdapGroupSearchFilter);
    WriteLogFile( pLdapProperties,1040, 'D', "Using search filter: %s\n", filter);
    WriteLogFile( pLdapProperties,1052, 'D', "pLdapProperties->LdapBaseDn: %s\n", pLdapProperties->LdapBaseDn);
    
    // Do the LDAP search
    struct timeval timeout = {pLdapProperties->SearchTimeout,0};
    result = ldap_search_ext_s(ldap, pLdapProperties->LdapBaseDn, LdapScope, filter, attrs, attrsonly, NULL, NULL, &timeout, 5, &answer);
    
    if ( result != LDAP_SUCCESS ) {
      WriteLogFile( pLdapProperties,1051, 'E', "ERROR: Search command (ldap_search_ext_s) failed: %s\n", ldap_err2string(result));
      //fprintf(stderr, "ldap_search_ext_s: %s\n", ldap_err2string(result));
      return(FALSE);
    } else {
      WriteLogFile( pLdapProperties,1050, 'D', "LDAP search completed.\n");
    }
  
    // Return the number of objects found during the search
    entries_found = ldap_count_entries(ldap, answer);
    if ( entries_found == 0 ) {
      WriteLogFile( pLdapProperties,1061, 'E', "ERROR: LDAP search did not return any data\n");
      //fprintf(stderr, "LDAP search did not return any data.\n");
      ldap_msgfree(answer);
      ldap_unbind_ext(ldap, NULL, NULL);
      return(FALSE);
    } else {
      WriteLogFile( pLdapProperties,1060, 'D', "LDAP search returned %d objects.\n", entries_found);
      WriteLogFile( pLdapProperties,1070, 'D', "Confirmed user %s is member of required group(s) %s\n", ldap_user, pLdapProperties->LdapGroupSearchFilter);
      ldap_msgfree(answer);
      ldap_unbind_ext(ldap, NULL, NULL);
      return(TRUE);
    }
  }
  else
  {
    ldap_msgfree(answer);
    ldap_unbind_ext(ldap, NULL, NULL);
    return(TRUE);
  }
}
