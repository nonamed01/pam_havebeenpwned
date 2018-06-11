# pam_havebeenpwned

This PAM security module integrates the [IHaveBeenPwned API]
(https://haveibeenpwned.com/)  written by
@Troy Hunt into PAM. Every time a user types a new password, a call to
the API is made. If the password has been pwned, the module
returns **PAM_AUTHOK_ERROR** and the password is not changed.

This module leverages their [**K-Anonymity password database**]
(https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/#cloudflareprivacyandkanonymity)

# Build & Install

* Install the **pre-requisites** first:

	apt-get install libssl-dev libcurl4-openssl-dev libpam-dev

* Then, build & install the module:

	git clone https://github.com/nonamed01/pam_havebeenpwned.git

	cd pam_havebeenpwned

	make

	su -c "make install"

* Edit **/etc/pam.d/common-passwd** and add the following line BEFORE the
  first pam_unix.so entry:

	password requisite pam_havebeenpwned.so [options]

* Append "try_first_pass" to the first pam_unix.so entry, so that the line
	right beneath the pam_havebeenpwned.so entry looks like this:

	password        [success=1 default=ignore]      pam_unix.so obscure sha512 try_first_pass

	
# Module options

	* debug.	If present, you will get debugging messages through /var/log/auth.log

	* minlen.	The minimum password length. By default, 6 characters.

	EXAMPLE:
	
	password requisite pam_havebeenpwned.so minlen=8 debug

# Demonstration

![Screenshot](screenshot.png)

