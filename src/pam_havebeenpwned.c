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
// COMPILING: run ./buildPam.sh
// INSTALLING: add the following line to /etc/pam.d/common-password BEFORE pam_unix.so
//
// password	requisite pam_havebeenpwned.so [options]
//
// Then, append the following enty to pam_unix.so: try_first_pass
//
// password requisite pam_havebeenpwned.so [options] (see below for options)
// password        [success=1 default=ignore]      pam_unix.so obscure sha512 try_first_pass
//
//
//	WARNING: This is a PoC, so don't use this module on a real system. Messing up with
//			 PAM can lead to a total system lockdown or even worse; a total compromised
//			 system. Feel free to modify, improve and secure this module and always
//			 test it ON a virtualised system. Take snapshots regularly to be able to
//			 step back if need be.
//
//
// REQUISITES:
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

// This is the default URL of the API.
#define HAVEBEENPWNED_URL "https://api.pwnedpasswords.com/range/%s"

// Default minim password length:
#define CO_MIN_LENGTH_BASE 6

// By default, enable debugging messages.
#define CO_PAM_DEBUG 0

// This is the memory struct we will use to store CURL's response:
struct MemoryStruct {
  char *memory;				// Pointer to the whole body response
  size_t size;				// Size of memory.
};

// This is the module options
struct havebeenpwned_options {
	unsigned int havebeenpwned_min_length;			// Minimum password length.
	unsigned int havebeenpwned_debug;				// If 0, no debugging messages at all.
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
//--------------------------------------------------------------------------------------------
static int _pam_parse (pam_handle_t *pamh, struct havebeenpwned_options *opt,
	int argc, const char **argv){

	int ctrl = 0;

	// step trhough arguments:
	for(ctrl=0;argc-- >0;++argv){
		char *ep = NULL;
		/* Min length; it should be at least > CO_MIN_LENGTH_BASE */
		if(!strncmp(*argv,"minlen=",7)){
			opt->havebeenpwned_min_length = strtol(*argv+7,&ep,10);
			if(!ep || (opt->havebeenpwned_min_length < CO_MIN_LENGTH_BASE))
				opt->havebeenpwned_min_length = CO_MIN_LENGTH_BASE;
		}
		/* debug; when this option is present, add debugging messages to /var/log/auth.log */
		else if (!strncmp(*argv,"debug",5)){
			opt->havebeenpwned_debug = 1;
		}
	} return ctrl;

}

// The main thing: here we will send our Curl HTTP GET request with the SHA1 of the password.
// The PAM library calls this function twice in succession. The first time with PAM_PRELIM_CHECK and then, if the module does not return
// PAM_TRY_AGAIN, subsequently with PAM_UPDATE_AUTHTOK. It is only on the second call that the authorization token is (possibly) changed.
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv){

	int retval;
	unsigned int ctrl, i;
	const void *oldtoken = NULL;				// Old password
	const char *newtoken = NULL;				// New password

	struct havebeenpwned_options options;		// Module options
	
    unsigned char temp[SHA_DIGEST_LENGTH];		// The SHA1 of the new password
	char buf[SHA_DIGEST_LENGTH*2];				// The SHA1 of the new password as a string

	// URL for the API:
	char GET[43];						// GET request is 43 + '\0'
	char PAYLOAD[6];					// The Hash to look for, 5 + '\0'
	char CHECK[36];						// The rest of the hash (35 + '\0')

	// CURL object:
	CURL *curl;
	CURLcode res;
	struct MemoryStruct chunk;

	// Initialize default options
	memset(&options,0,sizeof(options));
	options.havebeenpwned_min_length = CO_MIN_LENGTH_BASE;
	options.havebeenpwned_debug =  CO_PAM_DEBUG;

	// Process options:
	ctrl = _pam_parse(pamh,&options,argc,argv);

	// Show which call this module is in now:
	if(options.havebeenpwned_debug)
		pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: PAM module start: %s]",
			(flags&PAM_PRELIM_CHECK)?"PAM_PRELIM_CHECK":"PAM_UPDATEAUTHOK");

	// First call to this module has flag PAM_PRELIM_CHECK; we do nothing here;
	// Once the second call to this module is made, flags = PAM_UPDATE_AUTHTOK;
	// then we do all the checkings.
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

		// Asks for a new password now, store it to newtoken:
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
			pam_error(pamh,"Cannot compute SHA1(new_password");
			return PAM_AUTHTOK_ERR;	
		}
		// Transform the hash into a 40-byte hexadecimal uppercase string:
    	for (i=0; i < SHA_DIGEST_LENGTH; i++)
			sprintf((char*)&(buf[i*2]), "%02X", temp[i]);
		if(options.havebeenpwned_debug)
			pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: newtoken SHA1: %s]", buf);

		// We divide the SHA1 in two parts; the PAYLOAD to query the API
		// and the rest of it to make a local comparison later on with CURL response.
		strncpy(PAYLOAD,buf,5); PAYLOAD[5]='\0';					// the string to look for
		strncpy(CHECK,buf+5,35); CHECK[35] = '\0';					// The hash to compare to locally
		if(options.havebeenpwned_debug){
			pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: newtoken SHA1:0:5  %s]", PAYLOAD);
			pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: newtoken SHA1:5:40 %s]", CHECK);
		}
		snprintf(GET,43,HAVEBEENPWNED_URL,PAYLOAD); GET[42]='\0';				// We construct the query for CURL
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
			// Send the HTTP GET query:
			res = curl_easy_perform(curl);
			if(res!=CURLE_OK){
				if(options.havebeenpwned_debug)
					pam_syslog(pamh,LOG_ERR,"[HAVEIBEENPWNED: curl_easy_perform error: %s]",
						curl_easy_strerror(res));	
				// So we've got a CURL error. We should clean and exit with error:
				curl_easy_cleanup(curl);
				curl_global_cleanup();
				free(chunk.memory);
				pam_error(pamh,"CURL ERROR!");
				return PAM_AUTHTOK_ERR;
			}
			if(options.havebeenpwned_debug)
				pam_syslog(pamh,LOG_INFO,"[HAVEIBEENPWNED: curl received bytes: %lu]",chunk.size);
			//Cleanup:
			curl_easy_cleanup(curl);
			curl_global_cleanup();
			// We have the response in our chunk structure:
			if(strstr(chunk.memory,CHECK)){
				free(chunk.memory);
				pam_error(pamh,"THIS PASSWORD HAS BEEN PWNED!");
				// We reset the new password to NULL (so no change):
				pam_set_item(pamh, PAM_AUTHTOK, NULL);
				return PAM_AUTHTOK_ERR;
			}else{
				// We free the memory reserved:
				free(chunk.memory);
				// We can show output to the user:
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
			free(chunk.memory);
			// Impossible to initialise curl:
			if(options.havebeenpwned_debug)
				pam_syslog(pamh,LOG_ERR,"[HAVEIBEENPWNED: curl initialisation error]");
			pam_set_item(pamh, PAM_AUTHTOK, NULL);
			return PAM_AUTHTOK_ERR;
		} return PAM_AUTHTOK_ERR;
	}else 
		// Do nothing here, just return success:
		return PAM_SUCCESS;
}
