//=======================================================================
// MQSeries LDAP Security Channel Exit header
// Requires OpenLDAP 
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

#define     TRUE                1
#define     FALSE               0

typedef   signed short        SHORT;
typedef   unsigned char       UBYTE;
typedef   unsigned short      USHORT;
typedef   unsigned long       ULONG;

#ifndef _WIN32
typedef   unsigned char       BOOL;

#endif

#ifdef  MLDEBUG
# define D(x) x                 /* expand only when debugging     */
# define ND(x)                  /* expand only when not debugging */
#else
# define D(x)
# define ND(x) x
#endif

#ifdef WIN32
#define PROPERTY_FILENAME		"C:\\Program Files\\IBM\WebSphere MQ\\exits64\\libMQAuthLdap.properties"
#define LOG_PATH			"C:\\Program Files\\IBM\WebSphere MQ\\errors\\"
#define TMP_PATH			"c:\\tmp\\"
#else
#define SERVER_PROPERTY_FILENAME	"/var/mqm/exits64/ldap.properties"
#define CLIENT_PROPERTY_FILENAME	"/var/mqm/exits64/client.properties"
#define LOG_PATH			"/var/mqm/errors/"
#endif

/*******************************************************/
/*  Defines                                            */
/*******************************************************/
#define NORMAL_TRAP                  1100
#define CRITICAL_TRAP                1200
#define CHANNEL_NAME                 "CHANNEL"
#define QMGR_NAME                    "QMGR"
#define LOGFILE_PATH                 "LogFilePath"
#define LOGFILE_TAG                  "LogFileTag"
#define DEFAULT_USER                 "DefaultUser"
#define DEFAULT_LOG_TAG              "initlog"
#define DEBUG                        "Debug"
#define EQUAL                        '='
#define RETURN                       13
#define LINEFEED                     10
#define PROP_LDAP_AUTH_METHOD              "PROP_LDAP_AUTH_METHOD"
#define PROP_LDAP_VERSION                  "PROP_LDAP_VERSION" 
#define PROP_LDAP_SCOPE                    "PROP_LDAP_SCOPE"
#define PROP_LDAP_SERVER_URL               "PROP_LDAP_SERVER_URL"
#define PROP_LDAP_PRINCIPAL_PREFIX         "PROP_LDAP_PRINCIPAL_PREFIX"
#define PROP_LDAP_PRINCIPAL_SUFFIX         "PROP_LDAP_PRINCIPAL_SUFFIX"
#define PROP_LDAP_BASE_DN      	           "PROP_LDAP_BASE_DN"
#define PROP_LDAP_GROUP_SEARCH_FILTER      "PROP_LDAP_GROUP_SEARCH_FILTER"
#define PROP_LDAP_USER_SEARCH_ATTRIBUTE    "PROP_LDAP_USER_SEARCH_ATTRIBUTE"
#define PROP_LDAP_OPT_X_TLS_CACERTFILE     "PROP_LDAP_OPT_X_TLS_CACERTFILE"	
#define PROP_LDAP_OPT_X_TLS_CACERTDIR      "PROP_LDAP_OPT_X_TLS_CACERTDIR"
#define PROP_LDAP_OPT_X_TLS_REQUIRE_CERT   "PROP_LDAP_OPT_X_TLS_REQUIRE_CERT"
#define	PROP_LDAP_OPT_TIMELIMIT		   "PROP_LDAP_OPT_TIMELIMIT"
#define PROP_LDAP_OPT_REFERRALS		   "PROP_LDAP_OPT_REFERRALS"
#define PROP_LDAP_OPT_NETWORK_TIMEOUT	   "PROP_LDAP_OPT_NETWORK_TIMEOUT"
#define PROP_CHECK_HOST_ADDRESS		   "PROP_CHECK_HOST_ADDRESS"
#define PROP_AUTHENTICATE_USER	   	   "PROP_AUTHENTICATE_USER"
#define PROP_HOST_ADDRESS_RULE_FILE_FORMAT "PROP_HOST_ADDRESS_RULE_FILE_FORMAT"
#define PROP_HOST_ADDRESS_RULE_FILE_NAME   "PROP_HOST_ADDRESS_RULE_FILE_NAME"
#define CONNECTION_NAME			   "CON"
#define BUFSIZE 		    	   64
#define TOKENS 				   ";"
#define NI_MAXHOST 			   1025

typedef struct
{
	unsigned int 	errorno;
	char         	*errmsg;

} MQRE_MSG;

// Define structure for the LDAP Exit Properties
typedef struct 
{   

    char	QMgrName[48];   
    char	ChannelName[24];
    char	CheckHostAddress[24];
    char	AuthenticateUser[24];
    char	HostAddressRuleFileFormat[24];
    char	HostAddressRuleFileName[256];
    char	ConnectionName[264];
    char	ConnectionHostName[264];
    int		doDebugging;
    char	LogFilePath[256];
    char	LogFileName[256];
    char	LogFileTag[256]; 
    char	LdapServerUrl[256];
    char	LdapPrincipalPrefix[256];
    char	LdapPrincipalSuffix[256];
    char	LdapBaseDn[256];
    char	LdapGroupSearchFilter[1024];
    char	LdapUserSearchAttribute[256];
    int		LdapAuthMethod;
    int		LdapVersion;
    int		LdapScope;
    int		LdapNetworkTimeout;
    char	TLS_CACertFile[256];
    char	TLS_CACertDir[256];
    int		TLS_RequireCert;
    char	TLS_RequireCertString[256];
    char	LdapReferalOptString[256];
    int 	SearchTimeout;
    	
} LDAP_PROPERTIES;

#define LDAP_PROPERTIES_SIZE sizeof(LDAP_PROPERTIES)
typedef LDAP_PROPERTIES *pLDAP_PROPERTIES;

// Define structure for the LDAP Exit Properties
typedef struct 
{   
    char	ipAddress[264];
    char	shortHostName[1025];
    char	longHostName[1025];
    	
} HOSTINFO;

#define HOSTINFO_SIZE sizeof(HOSTINFO)
typedef HOSTINFO *pHOSTINFO;

