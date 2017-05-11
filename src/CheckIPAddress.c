//=======================================================================
// MQSeries LDAP Security Channel Exit support
// Name: CheckIPAdress.c
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
#include <regex.h>

// Prototypes                             
BOOL CheckIPAdress(PMQCD pChDef, pLDAP_PROPERTIES  pLdapProperties );
void WriteLogFile( pLDAP_PROPERTIES  pLdapProperties, int msgid, unsigned char msgtype, char *msgtxt,...);
void MakeCString( char *bf, char *zt, int len );
void GetHostName( pHOSTINFO pHostInfo, pLDAP_PROPERTIES );

//------------------------------------------------------------------
//   CheckIPAdress() - Check the IP adress of the connecting partner
//------------------------------------------------------------------
BOOL CheckIPAdress( PMQCD pChDef, pLDAP_PROPERTIES pLdapProp )
{
    
  FILE *prop_fp;
  char *ptr, *name_ptr;
  char field_val[1024], Prop_s[1024], fn[1024];
  short len;
  int chl_count = 0;		// Initialise property loop counter
  int state;
  BOOL qmgr_ok = FALSE;
  BOOL channel_ok = FALSE;
  char *tmp_char_field;
  static int  doDebugging = 1;
  static char Debug[256];
  char property_filename[129];
  char prop_filename[129];
  char *buf_pp = NULL;

  // Just return TRUE if we don't need to check the host address
  if (!strncmp (pLdapProp->CheckHostAddress, "FALSE",5))
  {
    WriteLogFile( pLdapProp,709, 'D', "CheckHostAddress is set to %s\n", pLdapProp->CheckHostAddress);
    return TRUE;
  }

  memset (Prop_s, 0, sizeof (Prop_s));
  WriteLogFile( pLdapProp,702, 'D', "Reading host rule file %s\n", pLdapProp->HostAddressRuleFileName);
  if ((prop_fp = fopen (pLdapProp->HostAddressRuleFileName, "r")) == NULL)
  {
    WriteLogFile( pLdapProp,703, 'E', "ERROR: Unable to open host rule file %s\n", pLdapProp->HostAddressRuleFileName);
    return FALSE;
  }

  /* read the property file until eof */
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
      
        if (!strcmp (QMGR_NAME, Prop_s))
        {
        
            char *allowedqmgr = NULL;
            allowedqmgr=(char*)strtok_r(field_val,";", &buf_pp);
            if ((!strcmp (allowedqmgr, pLdapProp->QMgrName)))
            {
              WriteLogFile( pLdapProp,704, 'D', "IP Property - Entry for Queue Manager %s found\n", field_val);
              qmgr_ok = TRUE;
            }
            else
            {
              qmgr_ok = FALSE;
            }
        }
      
        if (!strcmp (CHANNEL_NAME, Prop_s))
        {
            char *allowedchannel = NULL;
            allowedchannel=(char*)strtok_r(field_val,";", &buf_pp);
            if ((!strcmp (allowedchannel, pLdapProp->ChannelName)))
            {
              WriteLogFile( pLdapProp,705, 'D', "IP Property - Entry for Channel %s found\n", field_val);
              channel_ok = TRUE;
            }
            else
            {
              channel_ok = FALSE;
            }
        }
      
        if (!strcmp (CONNECTION_NAME, Prop_s))
        {	
          char *pAllowedhost = NULL;
          
          // Get the hostname for the connecting client 
          pHOSTINFO pHostInfo = NULL;
          pAllowedhost=(char*)strtok_r(field_val,";", &buf_pp);
          pHostInfo = (pHOSTINFO) malloc (HOSTINFO_SIZE+1);
          strcpy (pHostInfo->ipAddress, pAllowedhost);
          GetHostName( pHostInfo, pLdapProp);
              
          WriteLogFile( pLdapProp,706, 'D', "IP Property - ConnectionName = %s(%s)\n", pHostInfo->shortHostName, pAllowedhost);
          // Match on either the IP address or the hostname
          if ( qmgr_ok && channel_ok && ( (!strcmp (pAllowedhost, pLdapProp->ConnectionName) || (!strcmp (pAllowedhost, pLdapProp->ConnectionHostName) ))) ) 
          {
            WriteLogFile( pLdapProp,707, 'D', "SUCCESS: ConnectionName %s(%s) is authorised\n", pLdapProp->ConnectionHostName, pLdapProp->ConnectionName);
            fclose( prop_fp );
            return TRUE;
          }
        }
    }
    
    memset (Prop_s, 0, sizeof (Prop_s));
    memset (field_val, 0, sizeof (field_val));
    
    WriteLogFile( pLdapProp,708, 'E', "ERROR: No connection rule found for %s(%s)\n", pLdapProp->ConnectionHostName, pLdapProp->ConnectionName);
    fclose( prop_fp );
    return FALSE;
}
