#include <stdio.h>
#include <pwd.h>

#include "passwd.h"

struct passwd config_type_passwd_converter(
	const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data)
{
	printf("input: %s\n", input);
	
	struct passwd *pwd;
	pwd = getpwnam(input);

	if (pwd == NULL)
	{
		LOG(LOG_ERR, "can't find user: %s", input);
		return *pwd;
	}

	printf("[+] TEST [+]\n");
	printf("user in config: %s", input);
	printf("user retrieved: %s (%d)", pwd->pw_name, pwd->pw_uid);

	return *pwd;
}