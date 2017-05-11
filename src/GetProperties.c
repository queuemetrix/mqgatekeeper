//=======================================================================
// MQSeries LDAP Security Channel Exit support
// Name: GetProperties.c
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
BOOL GetProperties( PMQCD pChDef, pLDAP_PROPERTIES  pLdapProperties ); // Read the Property file
void GetHostName( pHOSTINFO pHostInfo, pLDAP_PROPERTIES );
void WriteLogFile( pLDAP_PROPERTIES  pLdapProperties, int msgid, unsigned char msgtype, char *msgtxt,...);
void MakeCString( char *bf, char *zt, int len );
void BuildFinalLogFileName( pLDAP_PROPERTIES  pLdapProperties );

//-----------------------------------------------------------
//   GetProperties() - read information from property file
//-----------------------------------------------------------
BOOL GetProperties( PMQCD pChDef, pLDAP_PROPERTIES  pLdapProp )
{
    
  FILE *prop_fp;
  char *ptr, *name_ptr;
  char field_val[1024], Prop_s[1024], fn[1024];
  short len;
  int chl_count = 0;		// Initialise property loop counter
  int qmgr_count = 0;
  int state;
  char *tmp_char_field;
  char ChlName[129];
  static int  doDebugging = 1;
  static char Debug[8];
  char property_filename[129];
  char SecurityUserData[48];
  
  #define ScanForQmgr 0
  #define ScanForChannel 1
  #define GetLdapValues 2

  memset (Debug, 0, sizeof (Debug));
  memset (Prop_s, 0, sizeof (Prop_s));
  memset (field_val, 0, sizeof (field_val));
  memset (pLdapProp->LogFilePath, 0, sizeof (pLdapProp->LogFilePath));
  memset (pLdapProp->LogFileName, 0, sizeof (pLdapProp->LogFileName));
  memset (pLdapProp->LogFileTag, 0, sizeof (pLdapProp->LogFileTag));
  memset (pLdapProp->LdapServerUrl, 0, sizeof (pLdapProp->LdapServerUrl));
  memset (pLdapProp->LdapPrincipalPrefix, 0, sizeof (pLdapProp->LdapPrincipalPrefix));
  memset (pLdapProp->LdapPrincipalSuffix, 0, sizeof (pLdapProp->LdapPrincipalSuffix));
  memset (pLdapProp->LdapBaseDn, 0, sizeof (pLdapProp->LdapBaseDn));
  memset (pLdapProp->LdapGroupSearchFilter, 0, sizeof (pLdapProp->LdapGroupSearchFilter));
  memset (pLdapProp->LdapUserSearchAttribute, 0, sizeof (pLdapProp->LdapUserSearchAttribute));
  memset (pLdapProp->TLS_CACertFile, 0, sizeof (pLdapProp->TLS_CACertFile));
  memset (pLdapProp->TLS_CACertDir, 0, sizeof (pLdapProp->TLS_CACertDir));
  memset (pLdapProp->ChannelName, 0, sizeof (pLdapProp->ChannelName));
  memset (pLdapProp->QMgrName, 0, MQ_Q_MGR_NAME_LENGTH);
  memset (pLdapProp->HostAddressRuleFileFormat, 0, sizeof (pLdapProp->HostAddressRuleFileFormat));
  memset (pLdapProp->HostAddressRuleFileName, 0, sizeof (pLdapProp->HostAddressRuleFileName));
  memset (pLdapProp->ConnectionName, 0, sizeof (pLdapProp->ConnectionName));
  memset (pLdapProp->CheckHostAddress, 0, sizeof (pLdapProp->CheckHostAddress));
  
  
  strcpy (property_filename, "/var/mqm/exits64/"); 
  pLdapProp->doDebugging = 0;     // Set debugging default to off
  
  // Get the ; seperated SecurityUserData values
  char *buf_pp = NULL;
  char *SecurityUserDataField = NULL;
  int FieldNumber=0;
  MakeCString (SecurityUserData, pChDef->SecurityUserData,sizeof (pChDef->SecurityUserData));
  SecurityUserDataField=(char*)strtok_r(SecurityUserData,";", &buf_pp);  
  
  #define PropertyFile 0
  #define DebugFlag 1 
  while (SecurityUserDataField != NULL)
  {
  
    switch (FieldNumber)
    {
    
      case (PropertyFile): // First value is property file name
      
        strcat(property_filename, SecurityUserDataField);
        break;
           
      case (DebugFlag): // Second value is debug flag 0|1
      
        doDebugging = atoi( SecurityUserDataField );
        pLdapProp->doDebugging = doDebugging;
        break; 
        
    }
    
    FieldNumber++;
    SecurityUserDataField=(char*)strtok_r(NULL,";", &buf_pp);
    
  }
  // End
  
  MakeCString (ChlName, pChDef->ChannelName, sizeof (pChDef->ChannelName));
  MakeCString (pLdapProp->ChannelName, pChDef->ChannelName, sizeof (pChDef->ChannelName));
  MakeCString (pLdapProp->QMgrName, pChDef->QMgrName, MQ_Q_MGR_NAME_LENGTH);
  MakeCString (pLdapProp->ConnectionName, pChDef->ConnectionName, sizeof (pChDef->ConnectionName));
  
  // Get the hostname for the connecting client 
  pHOSTINFO pHostInfo = NULL;
  pHostInfo = (pHOSTINFO) malloc (HOSTINFO_SIZE+1);
  strcpy (pHostInfo->ipAddress, pLdapProp->ConnectionName);
  GetHostName( pHostInfo, pLdapProp);
  strcpy (pLdapProp->ConnectionHostName, pHostInfo->shortHostName);
  // end

  if (strlen (property_filename))	/* if Channel Exit defined property filename use it */
    strcpy (fn, property_filename);	
  else					/* otherwise use default property filename   */
    strcpy (fn, SERVER_PROPERTY_FILENAME);
    
  if (!strlen (pLdapProp->LogFilePath)){
    strcpy (pLdapProp->LogFilePath, LOG_PATH);
  }

  WriteLogFile( pLdapProp,761, 'D', "Reading LDAP property file %s\n", fn);
  if ((prop_fp = fopen (fn, "r")) == NULL)
  {
    WriteLogFile( pLdapProp,760, 'E', "ERROR: Unable to open LDAP property file %s\n", fn);
    return FALSE;
  }
  
  /* read the property file until eof */
  state = ScanForQmgr;
  while ((ptr = fgets (Prop_s, sizeof (Prop_s) - 1, prop_fp)) != NULL)
  {
    len = strlen (Prop_s);
    if (Prop_s[len - 1] == LINEFEED)
      Prop_s[len - 1] = 0;	/* null out '\n' */
    if ((name_ptr = strchr (Prop_s, EQUAL)) == NULL)	/* no '=' found */
      continue;
    ptr = name_ptr + 1;
    *name_ptr = 0;		/* set null for s[] */
    strcpy (field_val, ptr);
    /* remove comments and unwanted characters from data */
    while (*ptr)
    {
        if (*ptr == ' ')
        { /* stop at first space */
          *ptr = 0;
          break;
        }
        ptr++;
    }
    
    switch (state)
    {
    
      case (ScanForQmgr):
      
        if (!strcmp (QMGR_NAME, Prop_s))
        {/* Only get details for this channel */
            if ((!strcmp (field_val, pLdapProp->QMgrName)))
            {
              WriteLogFile( pLdapProp,765, 'D', "LDAP Property - Entry for Queue Manager, %s found\n", field_val);
              qmgr_count++;
              state = ScanForChannel;
            }
          }
        break;
    
      case (ScanForChannel):
      
        if (!strcmp (CHANNEL_NAME, Prop_s))
        {/* Only get details for this channel */
            if ((!strcmp (field_val, ChlName)))
            {
              WriteLogFile( pLdapProp,770, 'D', "LDAP Property - Entry for Channel, %s found\n", field_val);
              chl_count++;
              state = GetLdapValues;
            }
          }
        break;

      case (GetLdapValues):
      
        /*
        if (!strcmp (DEBUG, Prop_s))
        {	
          strcpy( Debug, field_val );
          doDebugging = atoi( Debug );
          pLdapProp->doDebugging = atoi( Debug );
          WriteLogFile( pLdapProp,780, 'D', "LDAP Property - doDebugging = %d\n", pLdapProp->doDebugging);
          state = GetLdapValues;
          break;
        }     
        */   
        
        if (!strcmp (LOGFILE_PATH, Prop_s))
        {	
          strcpy (pLdapProp->LogFilePath, field_val);
          WriteLogFile( pLdapProp,790, 'D', "LDAP Property - LogFilePath = %s\n", pLdapProp->LogFilePath);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (LOGFILE_TAG, Prop_s))
        {	
          strcpy (pLdapProp->LogFileTag, field_val);
          WriteLogFile( pLdapProp,791, 'D', "LDAP Property - LogFileTag = %s\n", pLdapProp->LogFileTag);
          state = GetLdapValues;
          break;
        }
        
/*          
        if (!strcmp (PROP_LDAP_AUTH_METHOD, Prop_s))
        {
          if (!strncmp (field_val, "LDAP_AUTH_SIMPLE",16))
          {
          	LdapAuthMethod = LDAP_AUTH_SIMPLE;
          }
          WriteLogFile( pLdapProp,691, 'D', "LdapAuthMethod = %i\n", LdapAuthMethod);
          state = GetLdapValues;
          break;
        }
*/          

        if (!strcmp (PROP_LDAP_VERSION, Prop_s))
        {
          if (!strncmp (field_val, "LDAP_VERSION1",13))
          {
          	pLdapProp->LdapVersion = LDAP_VERSION1;
          }
          else if (!strncmp (field_val, "LDAP_VERSION2",13))
          {
          	pLdapProp->LdapVersion = LDAP_VERSION2;
          }
          else if (!strncmp (field_val, "LDAP_VERSION3",13))
          {
          	pLdapProp->LdapVersion = LDAP_VERSION3;
          }
          WriteLogFile( pLdapProp,800, 'D', "LDAP Property - LdapVersion = LDAP_VERSION%i\n", pLdapProp->LdapVersion);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_LDAP_OPT_X_TLS_REQUIRE_CERT, Prop_s))
        {
          strcpy (pLdapProp->TLS_RequireCertString, field_val);
          if (!strncmp (field_val, "LDAP_OPT_X_TLS_NEVER",20))
          {
          	pLdapProp->TLS_RequireCert = LDAP_OPT_X_TLS_NEVER;
          }
          else if (!strncmp (field_val, "LDAP_OPT_X_TLS_HARD",19))
          {
          	pLdapProp->TLS_RequireCert = LDAP_OPT_X_TLS_HARD;
          }
          else if (!strncmp (field_val, "LDAP_OPT_X_TLS_DEMAND",21))
          {
          	pLdapProp->TLS_RequireCert = LDAP_OPT_X_TLS_DEMAND;
          }
          else if (!strncmp (field_val, "LDAP_OPT_X_TLS_ALLOW",20))
          {
          	pLdapProp->TLS_RequireCert = LDAP_OPT_X_TLS_ALLOW;
          }
          else if (!strncmp (field_val, "LDAP_OPT_X_TLS_TRY",18))
          {
          	pLdapProp->TLS_RequireCert = LDAP_OPT_X_TLS_TRY;
          }
          WriteLogFile( pLdapProp,550, 'D', "LDAP Property - TLS_RequireCert = %s\n", pLdapProp->TLS_RequireCertString);
          state = GetLdapValues;
          break;
        }
/*        
        if (!strcmp (PROP_LDAP_SCOPE, Prop_s))
        {
          LdapScope = atoi( field_val );
          WriteLogFile( pLdapProp,691, 'D', "LdapScope = %s\n", LdapScope);
          state = GetLdapValues;
          break;
        }	    
*/          
        if (!strcmp (PROP_LDAP_OPT_X_TLS_CACERTFILE, Prop_s))
        {
          strcpy (pLdapProp->TLS_CACertFile, field_val);
          WriteLogFile( pLdapProp,810, 'D', "LDAP Property - TLS_CACertFile = %s\n", pLdapProp->TLS_CACertFile);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_HOST_ADDRESS_RULE_FILE_FORMAT, Prop_s))
        {
          strcpy (pLdapProp->HostAddressRuleFileFormat, field_val);
          WriteLogFile( pLdapProp,811, 'D', "LDAP Property - HostAddressRuleFileFormat = %s\n", pLdapProp->HostAddressRuleFileFormat);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_HOST_ADDRESS_RULE_FILE_NAME, Prop_s))
        {
          strcpy (pLdapProp->HostAddressRuleFileName, field_val);
          WriteLogFile( pLdapProp,812, 'D', "LDAP Property - HostAddressRuleFileName = %s\n", pLdapProp->HostAddressRuleFileName);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_CHECK_HOST_ADDRESS, Prop_s))
        {
          strcpy (pLdapProp->CheckHostAddress, field_val);
          WriteLogFile( pLdapProp,813, 'D', "LDAP Property - CheckHostAddress = %s\n", pLdapProp->CheckHostAddress);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_AUTHENTICATE_USER, Prop_s))
        {
          strcpy (pLdapProp->AuthenticateUser, field_val);
          WriteLogFile( pLdapProp,813, 'D', "LDAP Property - AuthenticateUser = %s\n", pLdapProp->AuthenticateUser);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_LDAP_OPT_X_TLS_CACERTDIR, Prop_s))
        {
          strcpy (pLdapProp->TLS_CACertDir, field_val);
          WriteLogFile( pLdapProp,820, 'D', "LDAP Property - TLS_CACertDir = %s\n", pLdapProp->TLS_CACertDir);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_LDAP_SERVER_URL, Prop_s))
        {			
          strcpy (pLdapProp->LdapServerUrl, field_val);
          WriteLogFile( pLdapProp,830, 'D', "LDAP Property - LdapServerUrl = %s\n", pLdapProp->LdapServerUrl);
          state = GetLdapValues;
          break;
        }	
          
        if (!strcmp (PROP_LDAP_PRINCIPAL_PREFIX, Prop_s))
        {
          strcpy (pLdapProp->LdapPrincipalPrefix, field_val);
          WriteLogFile( pLdapProp,840, 'D', "LDAP Property - LdapPrincipalPrefix = %s\n", pLdapProp->LdapPrincipalPrefix);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_LDAP_OPT_REFERRALS, Prop_s))
        {
          strcpy (pLdapProp->LdapReferalOptString, field_val);
          WriteLogFile( pLdapProp,850, 'D', "LDAP Property - LdapReferalOpt = %s\n", pLdapProp->LdapReferalOptString);
          state = GetLdapValues;
          break;
        }	
        
        //pLdapProp->SearchTimeout = 3; // Set the default to 10sec
        if (!strcmp (PROP_LDAP_OPT_TIMELIMIT, Prop_s))
        {
          pLdapProp->SearchTimeout = atoi( field_val );
          WriteLogFile( pLdapProp,860, 'D', "LDAP Property - SearchTimeout = %i\n", pLdapProp->SearchTimeout);
          state = GetLdapValues;
          break;
        }
        
        //pLdapProp->LdapNetworkTimeout = 30; // Set the default to 30sec
        if (!strcmp (PROP_LDAP_OPT_NETWORK_TIMEOUT, Prop_s))
        {
          pLdapProp->LdapNetworkTimeout = atoi( field_val );
          WriteLogFile( pLdapProp,861, 'D', "LDAP Property - LdapNetworkTimeout = %i\n", pLdapProp->LdapNetworkTimeout);
          state = GetLdapValues;
          break;
        }
          
        if (!strcmp (PROP_LDAP_PRINCIPAL_SUFFIX, Prop_s))
        {
          strcpy (pLdapProp->LdapPrincipalSuffix, field_val);
          WriteLogFile( pLdapProp,870, 'D', "LDAP Property - LdapPrincipalSuffix = %s\n", pLdapProp->LdapPrincipalSuffix);
          state = GetLdapValues;
          break;
        }	
          
        if (!strcmp (PROP_LDAP_BASE_DN, Prop_s))
        {
          strcpy (pLdapProp->LdapBaseDn, field_val);
          WriteLogFile( pLdapProp,880, 'D', "LDAP Property - LdapBaseDn = %s\n", pLdapProp->LdapBaseDn);
          state = GetLdapValues;
          break;
        }	  
          
        if (!strcmp (PROP_LDAP_GROUP_SEARCH_FILTER, Prop_s))
        {
          strcpy (pLdapProp->LdapGroupSearchFilter, field_val);
          WriteLogFile( pLdapProp,890, 'D', "LDAP Property - LdapGroupSearchFilter = %s\n", pLdapProp->LdapGroupSearchFilter);
          state = GetLdapValues;
          break;
        }
        
        if (!strcmp (PROP_LDAP_USER_SEARCH_ATTRIBUTE, Prop_s))
        {
          strcpy (pLdapProp->LdapUserSearchAttribute, field_val);
          WriteLogFile( pLdapProp,900, 'D', "LDAP Property - LdapUserSearchAttribute = %s\n", pLdapProp->LdapUserSearchAttribute);
          state = GetLdapValues;
          break;
        }		
        	       	  	    	    
        if (!strcmp (CHANNEL_NAME, Prop_s))
        {	/* Only get details for this channel */
          if ((strcmp (field_val, ChlName)))
          {
            WriteLogFile( pLdapProp,910, 'D', "New Channel %s found exiting properties\n", field_val);
            state = ScanForChannel;
            break;
          }
        }
      }
    }
    
    memset (Prop_s, 0, sizeof (Prop_s));
    memset (field_val, 0, sizeof (field_val));
       
    if (!strlen (pLdapProp->LogFileTag)){
      strcpy (pLdapProp->LogFileTag, DEFAULT_LOG_TAG);
    }
    
    if (!(chl_count)){
      WriteLogFile( pLdapProp,920, 'E', "ERROR: No LDAP property file entry for %s\n", ChlName);
      fclose( prop_fp );
      return FALSE;
    }
    fclose( prop_fp );
    return TRUE;
}

