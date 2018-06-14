//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// pam_havebeenpwned.c
//
//	PAM module to check if the new password to use has been pwned
//	using the IHaveBeenPwned API and its k-anonymity functionality.
//
//	2018 by Toni Castillo Girona
//  <toni.castillo at upc.edu>
//  http://disabauxes.upc.es
//	@disbauxes
//
// COMPILING: make && su -c "make install"
// INSTALLING: add the following line to /etc/pam.d/common-password BEFORE pam_unix.so
//
// password	requisite pam_havebeenpwned.so [options]
//
// Then, append the following enty to pam_unix.so: try_first_pass
//
// password requisite pam_havebeenpwned.so [options] (see below for options)
// password        [success=1 default=ignore]      pam_unix.so obscure sha512 try_first_pass
//
//	WARNING: This is a PoC, so don't use this module on a real system. Messing up with
//			 PAM can lead to a total system lockdown or even worse; a total compromised
//			 system. Feel free to modify, improve this module and always
//			 test it ON a virtualised system. Take snapshots regularly to be able to
//			 step back if needs be.
//
// BUILD REQUISITES:
//
// 			apt-get install libssl-dev libcurl4-openssl-dev libpam-dev
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <syslog.h>

// Version
#define VERSION	0.2

// This is the default URL of the API.
#define HAVEBEENPWNED_URL "https://api.pwnedpasswords.com/range/%s"

// Default minimum password length:
#define CO_MIN_LENGTH_BASE 6

// By default, disable debugging messages.
#define CO_PAM_DEBUG 0

// By default, don't process the number of times a password has been "seen":
#define CO_PASSWORD_SEEN 0

// Default timeout of 10 seconds:
#define CO_CURL_TIMEOUT 10

// By default, if there's an error communicating with the API,
// the module does not return an error and stacks the new password.
#define CO_ENFORCE_ON_ERROR 0

// This is the memory struct we will use to store CURL's response:
struct MemoryStruct {
  char *memory;				// Pointer to the whole body response
  size_t size;				// Size of memory.
};

// Module options
struct havebeenpwned_options {
	unsigned int havebeenpwned_min_length;			// Minimum password length.
	unsigned int havebeenpwned_debug;				// If 0, no debugging messages at all.
	unsigned int havebeenpwned_seen;				// If 1, it shows how many times a password has been seen
	unsigned long havebeenpwned_timeout;			// CURL timeout.
	unsigned int havebeenpwned_enforceonerror;		// If set to 1, it does not pass the new password to the
													// next module and exits with error even if CURL cannot
													// finish its request.
};

//--------------------------------------------------------------------------------------------
// WriteMemoryCallback
//	This function will process CURL's request response and store it to
//	mem->memory.
//  See https://curl.haxx.se/libcurl/c/getinmemory.html
//--------------------------------------------------------------------------------------------
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp){
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */ 
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

//--------------------------------------------------------------------------------------------
// _pam_parse
//	
//	Reads the options passed to the module in /etc/pam.d/common-password and sets up the
//	module accordingly
//
//	OPTIONS:
//		minlen=<LENGTH>; e.g.: minlen=8
//		debug
//		seen
//		timeout=<TIMEOUT>; e.g.: timeout=30
//--------------------------------------------------------------------------------------------
static int _pam_parse (pam_handle_t *pamh, struct havebeenpwned_options *opt,
	int argc, const char **argv){

	int ctrl = 0;

	// step trhough arguments:
	for(ctrl=0;argc-- >0;++argv){
		char *ep = NULL;
		/* Min length; it should be at least >= CO_MIN_LENGTH_BASE */
		if(!strncmp(*argv,"minlen=",7)){
			opt->havebeenpwned_min_length = strtol(*argv+7,&ep,10);
			if(!ep || (opt->havebeenpwned_min_length < CO_MIN_LENGTH_BASE))
				opt->havebeenpwned_min_length = CO_MIN_LENGTH_BASE;
		}
		/* debug; when this option is set, add debugging messages to /var/log/auth.log */
		else if (!strncmp(*argv,"debug",5)){
			opt->havebeenpwned_debug = 1;
		}
		/* Report how many times a password has been seen */
		else if (!strncmp(*argv,"seen",4)){
			opt->havebeenpwned_seen = 1;
		}
		/* Timeout */
		if(!strncmp(*argv,"timeout=",8)){
			opt->havebeenpwned_timeout = strtol(*argv+8,&ep,10);
			if(!ep || (opt->havebeenpwned_timeout < CO_CURL_TIMEOUT))
				opt->havebeenpwned_timeout = CO_CURL_TIMEOUT;
		}
		/* Enforce on error */
		else if (!strncmp(*argv,"enforceonerror",14)){
			opt->havebeenpwned_enforceonerror = 1;
		}
	} return ctrl;

}

//--------------------------------------------------------------------------------------------
// cleanup
//	
//	We overwrite CURL's chunk.data memory with zeros, and then we free it.
//  See http://www.linux-pam.org/Linux-PAM-html/mwg-see-programming-sec.html#mwg-see-programming-sec-token
//--------------------------------------------------------------------------------------------
int cleanup(pam_handle_t *pamh, void *data){
	char *pdata;
	if((pdata=data)){
		while(*pdata) *pdata++ = '\0';
		free(data);
	} return PAM_SUCCESS;
}

//--------------------------------------------------------------------------------------------
// pam_sm_chauthtok
//	
// The PAM library calls this function twice in succession. The first time with 
// PAM_PRELIM_CHECK and then, if the module does not return PAM_TRY_AGAIN, 
// subsequently with PAM_UPDATE_AUTHTOK.
//
// We do all the stuff when flags & PAM_UPDATE_AUTHTOK:
//
//	1) Get the current token.
//  2) Ask for a new one.
//  3) Compute its SHA1 hash.
//  4) Call IHaveBeenPwned API.
//  5) If the password is not pwned, confirm the new token.
//  6) If the two tokens match up, we set stack the new token.
//  7) On any other case, we do not stack the new token and return PAM_AUTHOK_ERR 	
//
//--------------------------------------------------------------------------------------------
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv){

	int retval;
	unsigned int i;
	const void *oldtoken = NULL;				// Old password
	const char *newtoken = NULL;				// New password

	struct havebeenpwned_options options;		// Module options
	
    unsigned char temp[SHA_DIGEST_LENGTH];		// The SHA1 of the new password
	char buf[SHA_DIGEST_LENGTH*2];				// The SHA1 of the new password as a string

	// URL for the API:
	char GET[43];						// GET request,  42 + '\0'
	char PAYLOAD[6];					// The Hash to look for, 5 + '\0'
	char CHECK[36];						// The rest of the hash, 35 + '\0'

	// CURL object:
	CURL *curl = NULL;
	CURLcode res;
	struct MemoryStruct chunk;

	char *hashfound = NULL;				// Only used if password_seen is set.
	char *hashfoundp = NULL;

	// Initialize default options
	memset(&options,0,sizeof(options));
	options.havebeenpwned_min_length = CO_MIN_LENGTH_BASE;
	options.havebeenpwned_debug =  CO_PAM_DEBUG;
	options.havebeenpwned_seen  =  CO_PASSWORD_SEEN;
	options.havebeenpwned_timeout  =  CO_CURL_TIMEOUT;
	options.havebeenpwned_enforceonerror = 	CO_ENFORCE_ON_ERROR;

	// Process options:
	_pam_parse(pamh,&options,argc,argv);

	// Show which call this module is in now:
	if(options.havebeenpwned_debug)
		pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: PAM module start: %s]",
			(flags&PAM_PRELIM_CHECK)?"PAM_PRELIM_CHECK":"PAM_UPDATEAUTHOK");

	// First call to this module has flag PAM_PRELIM_CHECK; we do nothing here;
	// Once the second call to this module is made, flags = PAM_UPDATE_AUTHTOK;
	// then we do all the stuff:
	if (flags & PAM_UPDATE_AUTHTOK){

		// Get the old password first:
		retval = pam_get_item (pamh, PAM_OLDAUTHTOK, &oldtoken);
		if (retval != PAM_SUCCESS) {
			pam_syslog(pamh,LOG_ERR,"Can not get old passwd");
			oldtoken = NULL;
		 	return PAM_AUTHTOK_ERR;
		}

		// We've got the old password:
		if(options.havebeenpwned_debug)
			pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: oldtoken OK]");

		// Asks for a new password now, save it to newtoken:
		retval = pam_get_authtok_noverify (pamh, &newtoken, NULL);
		if (retval != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_ERR, "pam_get_authtok_noverify returned error: %s",
				pam_strerror (pamh, retval));
		 	return PAM_AUTHTOK_ERR;
		// User has cancelled the changing of the password:
		} else if (newtoken == NULL) {
			return PAM_AUTHTOK_ERR;
		}

		//If password's length is < MINLEN chars, error:
		if(strlen(newtoken)<options.havebeenpwned_min_length){
			pam_error(pamh,"Password is too short!");
			return PAM_AUTHTOK_ERR;
		}

	    if(options.havebeenpwned_debug)
			pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: newtoken OK]");

		// Generate the SHA1 of this new password.
		memset(buf, 0x0, SHA_DIGEST_LENGTH*2);
		memset(temp, 0x0, SHA_DIGEST_LENGTH);
		// Make sure to return if the SHA1 cannot be computed:
		if(SHA1((unsigned char *)newtoken, strlen(newtoken), temp)==NULL){
			pam_error(pamh,"Cannot compute SHA1(new_password)");
			return PAM_AUTHTOK_ERR;	
		}
		// Transform the hash into a 40-byte hexadecimal uppercase string:
    	for (i=0; i < SHA_DIGEST_LENGTH; i++)
			sprintf((char*)&(buf[i*2]), "%02X", temp[i]);

		// We divide the SHA1 in two parts; the PAYLOAD to query the API
		// and the rest of it to make a local comparison later on with CURL's response.
		strncpy(PAYLOAD,buf,5);  PAYLOAD[5]='\0';					// the string to look for
		strncpy(CHECK,buf+5,35); CHECK[35] = '\0';					// The hash to compare to locally
		// snprintf also adds '\0' to the copy, but anyway we make sure to add it too:
		// This is the actual HTTP GET Request we will make using CURL:
		snprintf(GET,43,HAVEBEENPWNED_URL,PAYLOAD); GET[42]='\0';
		if(options.havebeenpwned_debug)
			pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: URL %s]", GET);

		// We initialize our memory structure to accomodate CURL's response:
		chunk.memory = malloc(1);
		chunk.size = 0;
		curl_global_init(CURL_GLOBAL_ALL);

		// Using CURL, we send the request. We need to make sure we find
		// the exact MATCH within CURL's response.
		curl = curl_easy_init();
		if(curl){
			curl_easy_setopt(curl, CURLOPT_URL,GET);
			// CURL's response will be processed by WriteMemoryCallback:
  			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
			// Set the timeout:
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, options.havebeenpwned_timeout);
			// Send the HTTP GET query:
			res = curl_easy_perform(curl);
			if(res!=CURLE_OK){
				if(options.havebeenpwned_debug)
					pam_syslog(pamh,LOG_ERR,"[HAVEIBEENPWNED: curl_easy_perform error: %s]",
						curl_easy_strerror(res));	
				// So we've got a CURL error. We should clean and exit with error:
				curl_easy_cleanup(curl);
				curl_global_cleanup();
				cleanup(pamh,chunk.memory);
				// Do we have enforceonerror == 0?
				if(options.havebeenpwned_enforceonerror){
					pam_error(pamh,"CURL or API ERROR; quitting...");
					return PAM_AUTHTOK_ERR;
				}else{
					// If enforceonerror is not set, just ask for confirmation and pass it on:
					pam_error(pamh,"CURL or API error; the password WON'T be checked.");
					// We make sure now the password is re-typed and it's the same one:
					retval = pam_get_authtok_verify (pamh, &newtoken, NULL);
					if (retval != PAM_SUCCESS) {
						pam_syslog(pamh, LOG_ERR, "pam_get_authtok_verify returned error: %s",
								pam_strerror (pamh, retval));
						pam_set_item(pamh, PAM_AUTHTOK, NULL);
						return PAM_AUTHTOK_ERR;
					}else if (newtoken == NULL) {	// User aborted password change
						return PAM_AUTHTOK_ERR;
					}
					// Stack the new password for the next module and return:
					pam_set_item(pamh,PAM_AUTHTOK,newtoken);
					return PAM_SUCCESS;
				}
			}
			if(options.havebeenpwned_debug)
				pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: curl received bytes: %lu]",chunk.size);
			//Cleanup:
			curl_easy_cleanup(curl);
			curl_global_cleanup();
			// We have the response in chunk.memory:
			if(NULL!=(hashfound=(strstr(chunk.memory,CHECK)))){
				// Get how many times the password has been seen?
				if(options.havebeenpwned_seen){
					if(NULL!=(hashfoundp = strtok(hashfound,":"))){
						// Next delimiter is \r\n:
						hashfoundp=strtok(NULL,"\r\n");
					}
				}
				cleanup(pamh,chunk.memory);
				// Show how many times the password has been seen (if hashfoundp!=NULL):
				if(options.havebeenpwned_seen && hashfoundp!=NULL)
					 pam_error(pamh,"THIS PASSWORD HAS BEEN PWNED %s TIMES!",  hashfoundp);
				else
					pam_error(pamh,"THIS PASSWORD HAS BEEN PWNED!");
				// We reset the new password to NULL (so no change):
				pam_set_item(pamh, PAM_AUTHTOK, NULL);
				return PAM_AUTHTOK_ERR;
			}else{
				cleanup(pamh,chunk.memory);
				pam_error(pamh,"OK: password has not been pwned (YET)");
				// We make sure now the password is re-typed and it's the same one:
				retval = pam_get_authtok_verify (pamh, &newtoken, NULL);
				if (retval != PAM_SUCCESS) {
					pam_syslog(pamh, LOG_ERR, "pam_get_authtok_verify returned error: %s",
							pam_strerror (pamh, retval));
					pam_set_item(pamh, PAM_AUTHTOK, NULL);
					return PAM_AUTHTOK_ERR;
				}else if (newtoken == NULL) {	// User aborted password change
					return PAM_AUTHTOK_ERR;
				}
				// We return sucess here and set the new password for the next module:
				pam_set_item(pamh,PAM_AUTHTOK,newtoken);
				return PAM_SUCCESS;
			}
		}else{
			// Impossible to initialise curl:
			cleanup(pamh,chunk.memory);
			if(options.havebeenpwned_debug)
				pam_syslog(pamh,LOG_ERR,"[HAVEIBEENPWNED: curl initialisation error]");
			pam_set_item(pamh, PAM_AUTHTOK, NULL);
			return PAM_AUTHTOK_ERR;
		} return PAM_AUTHTOK_ERR;
	}else 
		// Do nothing here, just return success:
		return PAM_SUCCESS;
}
