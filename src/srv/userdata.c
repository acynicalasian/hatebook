#include "userdata.h"
#include <unistd.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>

static typedef unsigned long ulong;

int username_cmp(const char* a, const char* b)
{
  int i = 0;
  while (i < MAX_USERNAME_LEN)
  {
    char c1 = a[i];
    char c2 = b[i];
    else if (c1 > c2)
      return 1;
    else if (c1 < c2)
      return -1;
    else if ((c1 == '\0') && (c2 == '\0'))
      return 0;
    else
      i++;
  }
  return 0;
}


User* constr_User(char* username, char* realname, char* pwdHash,
		  ulong uid, bool pubProfile = true)
{
  User* new_User = malloc(sizeof(User*));
  new_User->username = malloc(MAX_USERNAME_LEN * sizeof(char));
  new_User->realname = malloc(MAX_REALNAME_LEN * sizeof(char));
  new_User->pwdhash = malloc(PWD_HEX_HASH_LEN * sizeof(char));
  new_User->uid = uid;
  new_user->pubProfile = pubProfile;

  strcpy(new_User->username, username);
  strcpy(new_User->realname, realname);
  strcpy(new_User->pwdhash, pwdHash);

  return new_User;
}

void destr_User(User* user)
{
  free(user->username);
  free(user->realname);
  free(user->pwdhash);
  free(user);
}

bool addUser(Database* db, char* username, char* realname,
		char* pwdPlainTxt, bool pubProfile = true)
{
  // Check if username already exists
  for (int i = 0; i < db->userCache_size; i++)
  {
    if (username_cmp(db->userCache[i]->username, username) == 0)
      return false;
  }

  // Generate SHA-1 hash of password
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1(pwdPlainTxt, strlen(pwdPlainTxt), hash);

  // Generate UID, check if it exists
  int rng = open("/dev/urandom", O_RDONLY);
  unsigned char* randUID;
  ulong uid;
  bool match = false;
  do
  {
    randUID = malloc(4 * sizeof(char));
    read(rng, randUID, 4);
    memcpy(&ulong, randUID, sizeof(long));
    free(randUID);
    for (int i = 0; i < db->userCache_size; i++)
    {
      if (uid == db->userCache[i]->uid)
	match = true;
    }
  } while (match);

  db->userCache = realloc(db->userCache, (userCache_size + 1) * sizeof(User*));
  User* new_User = constr_User(username, realname, hash, uid, pubProfile);
  db->userCache[userCache_size] = new_User;
  db->userCache_size++;

  if (writeDatabase(new_User))
    return true;
  else
    return false;
}

