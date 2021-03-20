#ifndef USERDATA_H
#define USERDATA_H

#include <stdbool.h>
#include <openssl/sha.h>

static typedef unsigned long ulong;

extern const int MAX_USERNAME_LEN = 16;
extern const int MAX_REALNAME_LEN = 32;
extern const int PWD_HEX_HASH_LEN = SHA_DIGEST_LENGTH;

extern typedef struct User {
  char username[MAX_USERNAME_LEN];
  char realname[MAX_REALNAME_LEN];
  unsigned char pwdhash[PWD_HEX_HASH_LEN]; // Store passwords as an SHA-1 hash
  ulong uid; // Store user IDs as an unsigned 32-bit integer
  bool pubProfile;
} User;

extern typedef struct Database {
  char** pubRealnameCache; // Cache list of public users by their realname
  int pubRealnameCache_Size;
  User* userCache; // Cached list of all users
  int userCache_size;
} Database;

/* Function definitions for userdata and database management */
extern User* constr_User(char* username, char* realname, char* pwdHash,
		         ulong uid, bool pubProfile = true);

extern void destr_User(User* user);

extern bool addUser(Database* db, char* username, char* realname,
		       char* pwdPlainTxt, bool pubProfile = true);
extern bool delUser(Database* db, ulong uid);

extern Database* initDatabase();
extern bool writeDatabase(User* user);

#endif
