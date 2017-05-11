 //=======================================================================
// MQSeries LDAP Security Channel Exit support
// Name: libMQAuthLdap.c
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

// Global Variables                                   
//static char       logFileName[256];
static char       logFilePath[256];
char		  ChlName[129];
char		  ChlMCAUser[129];
static int     	  doDebugging = 1;
char		  User[256];
char		  Pass[256];
char		  initUser[256];
char		  initPass[256];
BOOL		  PROP_READ_OK = TRUE;
static int        firstTime = 1;
pLDAP_PROPERTIES  pLdapProperties = NULL;
pLDAP_PROPERTIES * ppLdapProperties;
pLDAP_PROPERTIES * ppExitUserArea; 
pLDAP_PROPERTIES  pExitUserArea;

// Prototypes                             
BOOL GetProperties( PMQCD pChDef, pLDAP_PROPERTIES  pLdapProperties ); // Read the Property file
BOOL LdapAuthenticateUser(char *ldap_user, char *ldap_pw, pLDAP_PROPERTIES  pLdapProperties); // Authenticate the user against LDAP
BOOL CheckIPAdress(PMQCD pChDef, pLDAP_PROPERTIES  pLdapProperties );
void GetHostName( pHOSTINFO pHostInfo, pLDAP_PROPERTIES );
void WriteLogFile( pLDAP_PROPERTIES  pLdapProperties, int msgid, unsigned char msgtype, char *msgtxt,...);
void PrintBuff( unsigned char *out, unsigned int len );
void MakeCString( char *bf, char *zt, int len );

// EXIT Entry points
void MQENTRY MQStart(void) {;}
void MQENTRY MQAuthLdap(  PMQVOID channelExitParms,
                          PMQVOID channelDef,
                          PMQLONG pDataLength,
                          PMQLONG pAgentBufferLength,
                          PMQVOID pAgentBuffer,
                          PMQLONG pExitBufferLength,
                          PMQPTR  pExitBufferAddr )
{

    PMQCXP       	pChlExParms 	= ( PMQCXP ) channelExitParms;
    PMQCD          	pChDef 		= ( PMQCD ) channelDef;
   
    //ppExitUserArea = (pLDAP_PROPERTIES*) &pChlExParms->ExitUserArea;
    //pLdapProperties  = *ppExitUserArea;
      
    /* 
    // Get the pointer to the properties    
    if (pChlExParms->ExitUserArea != MQXUA_NONE_ARRAY) 
    {
      pLdapProperties = (pLDAP_PROPERTIES*)pChlExParms->ExitUserArea;
      WriteLogFile( pLdapProperties,601,'D', "Setting pLdapProperties from pChlExParms->ExitUserArea\n");
    }
    */
    
    if ( firstTime  )
    {
        pLdapProperties = (pLDAP_PROPERTIES) malloc (LDAP_PROPERTIES_SIZE+1);
        PROP_READ_OK = GetProperties(pChDef,pLdapProperties); // Read the property file 
        //Save the pointer to the properties for subsequequent invocations     
        //memcpy(pChlExParms->ExitUserArea, &pLdapProperties, sizeof(MQBYTE16));
        firstTime = 0; 
    }
        
    switch ( pChlExParms->ExitId )
    {
      case MQXT_CHANNEL_SEC_EXIT:
        WriteLogFile( pLdapProperties,600,'D', ">>>>> MQAuthLdap exit started\n");
        break;
      default:
        WriteLogFile( pLdapProperties,610, 'E', "ERROR: Connection refused, unsupported ExitId = %i\n",pChlExParms->ExitId );
        pChlExParms->ExitResponse = MQXCC_SUPPRESS_FUNCTION;    // Return a failure
        break;
      } 

    switch ( pChlExParms->ExitReason )
    {
        case MQXR_INIT:
        
          WriteLogFile( pLdapProperties,620, 'D', "ExitReason = MQXR_INIT\n");
          //WriteLogFile( pLdapProperties,601,'D', "Reading properties file ..\n");      
          //PROP_READ_OK = GetProperties(pChDef,pLdapProperties); // Read the property file  
          break;
          
        case MQXR_SEC_PARMS:
        
          WriteLogFile( pLdapProperties,630, 'D', "ExitReason = MQXR_SEC_PARMS\n" ); 
          break;
          
        case MQXR_TERM:
           
          WriteLogFile( pLdapProperties,640, 'D', "ExitReason = MQXR_TERM\n" );
          WriteLogFile( pLdapProperties,641, 'I', "ENDED: Channel %s, ConnectionName = %s(%s)\n", pLdapProperties->ChannelName, pLdapProperties->ConnectionHostName, pLdapProperties->ConnectionName );
          //pLdapProperties = (pLDAP_PROPERTIES*)pChlExParms->ExitUserArea;
          //memcpy(pChlExParms->ExitUserArea, MQXUA_NONE,sizeof(MQBYTE16));
          break;
          
        case MQXR_SEC_MSG:
        
           WriteLogFile( pLdapProperties,650, 'D', "ExitReason = MQXR_SEC_MSG\n" );
           break;
           
        case MQXR_RETRY:
           
           WriteLogFile( pLdapProperties,660, 'D', "ExitReason = MQXR_RETRY\n" );
           break;
            
        case MQXR_INIT_SEC:
        
          WriteLogFile( pLdapProperties,670, 'D', "ExitReason = MQXR_INIT_SEC\n" );
          
          switch ( pChDef->ChannelType )
          {
          
            case MQCHT_SVRCONN:
               
                PROP_READ_OK = GetProperties(pChDef,pLdapProperties); // Read the property file
                WriteLogFile( pLdapProperties,680, 'D', "Channel type = MQCHT_SVRCONN\n" ); 		
                memset (User, 0, pChDef->LongRemoteUserIdLength);
                memset (Pass, 0, MQ_PASSWORD_LENGTH);
                MakeCString(User,pChDef->LongRemoteUserIdPtr,pChDef->LongRemoteUserIdLength);
                MakeCString(Pass,pChDef->RemotePassword,MQ_PASSWORD_LENGTH);                 
                WriteLogFile( pLdapProperties,690, 'D', "RemoteUserIdentifier = %s\n",User );
                WriteLogFile( pLdapProperties,691, 'D', "RemotePassword = ...\n" );
                WriteLogFile( pLdapProperties,692, 'D', "ConnectionName = %s(%s)\n",pLdapProperties->ConnectionHostName, pLdapProperties->ConnectionName );
                //WriteLogFile( pLdapProperties,611, 'D', "RemotePassword = %s\n",Pass );   
                                
                // Authenticate user on LDAP
                if ( ! LdapAuthenticateUser(User,Pass,pLdapProperties) ) {
                    //WriteLogFile( pLdapProperties,700, 'E', "ERROR: Connection refused, user authentication failed\n");
                    WriteLogFile( pLdapProperties,700, 'E', "ERROR: Connection refused, user authentication failed on Channel %s, %s@%s(%s)\n",pLdapProperties->ChannelName, User, pLdapProperties->ConnectionHostName, pLdapProperties->ConnectionName);
                    pChlExParms->ExitResponse = MQXCC_SUPPRESS_FUNCTION;    // Return a failure
                    WriteLogFile( pLdapProperties,701, 'D', "return(MQXCC_SUPPRESS_FUNCTION)\n" );
                    break;
                }else{
                    //Set the SVRCONN MCAUserIdentifier to the user trying to connect if the channel MCAUser property is blank                    
                    if( strlen (pChDef->MCAUserIdentifier) == 0 )
                    {  
                      strncpy (pChDef->MCAUserIdentifier, User, sizeof(User)); 
                    }                                 
                    //Print to std out, usually the MQ listener log
                    if(CheckIPAdress(pChDef,pLdapProperties))
                    { 
                      MakeCString (ChlMCAUser, pChDef->MCAUserIdentifier, sizeof (pChDef->MCAUserIdentifier));
                      WriteLogFile( pLdapProperties,710, 'I', "STARTED: Channel %s, ConnectionName = %s(%s), started by = %s, MCAUSER = %s\n",pLdapProperties->ChannelName, pLdapProperties->ConnectionHostName, pLdapProperties->ConnectionName, User, ChlMCAUser );                       
                      break; 
                    }
                    else
                    {
                      WriteLogFile( pLdapProperties,700, 'E', "ERROR: Connection refused, bad client IP address for Channel %s, %s(%s)\n",pLdapProperties->ChannelName, pLdapProperties->ConnectionHostName, pLdapProperties->ConnectionName);
                      WriteLogFile( pLdapProperties,701, 'D', "return(MQXCC_SUPPRESS_FUNCTION)\n" ); 
                      pChlExParms->ExitResponse = MQXCC_SUPPRESS_FUNCTION;    // Return a failure 
                      break;                 
                    }
                }
                	
    		break;
    		
            default:
          	WriteLogFile( pLdapProperties,720, 'E', "ERROR: Connection refused, unsupported Channel type = %i\n",pChDef->ChannelType );
          	pChlExParms->ExitResponse = MQXCC_SUPPRESS_FUNCTION;    // Return a failure 
          	break;
          	
          } /* endswitch ChannelType in MQXR_INIT_SEC */     

          break;
                 
        default:
        
           WriteLogFile( pLdapProperties,730, 'E', "ERROR: Connection refused, unknown Exit Reason code in channel security exit call = %i\n", pChlExParms->ExitReason);
           pChlExParms->ExitResponse = MQXCC_SUPPRESS_FUNCTION;    // Return a failure
           break;
    }
    return;
}

void WriteLogFile(pLDAP_PROPERTIES  pLdapProperties, int msgid,unsigned char msgtype, char *msgtxt, ... )
{
    static int    firstTime = 1;
    va_list  	  args;
    struct tm *timenow;
    struct tm  wk_localtime;
    time_t longtime;
    char todays_date[24];
    char todays_log[256];
    FILE *logFilePtr;;
        
    if ( pLdapProperties->doDebugging == 0 && msgtype == 'D' )
      return;

    memset(&wk_localtime, '\0', sizeof(wk_localtime));
    memset(&longtime, '\0', sizeof(longtime));
    time(&longtime);
    timenow = localtime_r(&longtime,&wk_localtime);    
    sprintf( todays_date, "-%02d-%02d-%04d",timenow->tm_mday, timenow->tm_mon+1, timenow->tm_year+1900);
    
    // Set the default log tag if not yet specified
    if (!strlen (pLdapProperties->LogFileTag)){
      strcpy (pLdapProperties->LogFileTag, DEFAULT_LOG_TAG);
    }
    
    // Set the default log path if not yet specified from the properties file
    if (!strlen (pLdapProperties->LogFilePath)){
      strcpy (pLdapProperties->LogFilePath, LOG_PATH);
    }
    
    // Build the log file name
    strcpy(todays_log, pLdapProperties->LogFilePath);
    strcat(todays_log, pLdapProperties->ChannelName);
    strcat(todays_log, "-");
    strcat(todays_log, pLdapProperties->QMgrName);
    strcat(todays_log, "-");
    strcat(todays_log, pLdapProperties->LogFileTag);
    strcat(todays_log, todays_date);
    strcat(todays_log, ".log");
    strcpy(pLdapProperties->LogFileName, todays_log); 

    if ( logFilePtr != stdout ) 
      if ( ( logFilePtr = fopen(todays_log,"a+") ) == NULL )
      {
        logFilePtr = stdout;
        WriteLogFile( pLdapProperties, 750, 'E',"ERROR: Connection refused, failed to open logfile %s.\n",todays_log);
        WriteLogFile( pLdapProperties, 751, 'I',"Using stdout for log messages\n");
        return;
      }
      
    int FileLocked = 1;
    //FileLocked = ftrylockfile(logFilePtr);
    
    //while(FileLocked)
    //{
    //  FileLocked = ftrylockfile(logFilePtr);
    //}
  
    fprintf( logFilePtr, "%02d-%02d-%04d %02d:%02d:%02d ",timenow->tm_mday, timenow->tm_mon+1, timenow->tm_year+1900,
    timenow->tm_hour, timenow->tm_min, timenow->tm_sec);

    fprintf( logFilePtr,"MOD9%03d%c %s MQAuthLdap ;", msgid, msgtype, pLdapProperties->QMgrName);
    va_start( args, msgtxt );
    vfprintf( logFilePtr, msgtxt, args);
    va_end (args);

    //funlockfile(logFilePtr);

    if ( logFilePtr != stdout )
	fclose(logFilePtr);
    else
	fflush(stdout);

}

/* Copy from a blank-filled array to a zero-terminated string */
void MakeCString( char *zt, char *bf, int len )
{
  int i;
  for ( i = 0; bf[i] != ' ' && i < len; i++ )
    zt[i] = bf[i];
    zt[i] = 0;
}




