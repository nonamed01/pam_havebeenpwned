CFLAGS+= -Wall
all: pam_havebeenpwned.so

clean:
	$(RM) pam_havebeenpwned.so pam_havebeenpwned.o

pam_havebeenpwned.so: src/pam_havebeenpwned.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl -lssl

install:
	cp -f pam_havebeenpwned.so /lib/x86_64-linux-gnu/security/pam_havebeenpwned.so && chmod 644 /lib/x86_64-linux-gnu/security/pam_havebeenpwned.so
	cp -f pam-configs/havebeenpwned /usr/share/pam-configs/
	cp -f man/pam_havebeenpwned.8 /usr/share/man/man8/ && gzip -f /usr/share/man/man8/pam_havebeenpwned.8
