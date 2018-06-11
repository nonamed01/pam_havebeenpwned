CFLAGS += -Werror 
all: pam_havebeenpwned.so

clean:
	$(RM) pam_havebeenpwned.so pam_havebeenpwned.o

pam_havebeenpwned.so: src/pam_havebeenpwned.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl -lssl

install:
	cp pam_havebeenpwned.so /lib/x86_64-linux-gnu/security/pam_havebeenpwned.so
