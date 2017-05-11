//=======================================================================
// MQSeries LDAP Security Channel Exit support
// Name: GetAddressInfo.c
// Desc: These functions allow the IP or Host name to be resolved
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
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

void WriteLogFile( pLDAP_PROPERTIES  pLdapProperties, int msgid, unsigned char msgtype, char *msgtxt,...);
void MakeCString( char *bf, char *zt, int len );
void GetHostName( pHOSTINFO pHostInfo, pLDAP_PROPERTIES );

void GetHostName( pHOSTINFO pHostInfo, pLDAP_PROPERTIES pLdapProp )
{
  //WriteLogFile( pLdapProp,706, 'D', "Getting name for IP address %s\n", pHostInfo->ipAddress);
  struct sockaddr_in sa;   
  sa.sin_family = AF_INET;   
  inet_pton(AF_INET, pHostInfo->ipAddress, &sa.sin_addr); 
  char fullhostname[NI_MAXHOST];
  int err=getnameinfo((struct sockaddr*)&sa,sizeof(sa),fullhostname,sizeof(fullhostname),0,0,0);
  
  if (err!=0) 
  {
      WriteLogFile( pLdapProp,709, 'E', "ERROR: Failed to convert ip address to name (code=%d)\n", err);
  }
  
  char *buf_pp = NULL;
  char *hostname;
  strcpy (pHostInfo->longHostName, fullhostname);
  hostname=(char*)strtok_r(fullhostname,".", &buf_pp); // Just grab the host name without the whole domain name
  strcpy (pHostInfo->shortHostName, hostname);
  //WriteLogFile( pLdapProp,706, 'D', "Hostname = %s\n", pHostInfo->shortHostName);
  
}

