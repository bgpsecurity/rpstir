/*
  $Id: manifest_validate.c 453 2007-07-25 15:30:40Z gardiner $
*/

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2008.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include "roa_utils.h"
#include "manifest.h"
#include "cryptlib.h"

/*
  This file contains the functions that semantically validate the ROA.
  Any and all syntactic validation against existing structures is assumed
  to have been performed at the translation step (see roa_serialize.c).
*/

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp)
  { 
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr = -1;

  memset(hash, 0, 40);
  cryptInit();
  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
  }


static int check_fileAndHash(struct FileAndHash *fahp, int ffd)
  {
  uchar *contentsp;
  int err = 0,
      hash_lth, bit_lth, name_lth = lseek(ffd, 0, SEEK_END);

  lseek(ffd, 0, SEEK_SET);
  contentsp = (uchar *)calloc(1, name_lth + 2);
  if (read(ffd, contentsp, name_lth + 2) != name_lth) err = ERR_SCM_BADFILE;
  else if ((hash_lth = gen_hash(contentsp, name_lth, contentsp)) < 0) 
    err = ERR_SCM_BADHASH;
  else
    {
    bit_lth = vsize_casn(&fahp->hash);
    uchar *hashp = (uchar *)calloc(1, bit_lth);
    read_casn(&fahp->hash, hashp);
    if (hash_lth != bit_lth - 1 || memcmp(&hashp[1], contentsp, hash_lth)) 
      err = ERR_SCM_BADHASH;
    free(hashp);
    close(ffd);
    }
  free(contentsp);
  return err;
  }
   
void free_badfiles(struct badfile **badfilespp)
  {
  struct badfile **bpp;
  for (bpp = badfilespp; *bpp; bpp++)
    {
    free((*bpp)->fname);
    free(*bpp);
    }
  free(badfilespp);
  }

int manifestValidate2(struct ROA *rp, char *dirp, struct badfile ***badfilesppp)
  {
  struct FileAndHash *fahp;
  struct Manifest *manp;
  struct Certificate *certp;
  struct badfile **badfilespp = (struct badfile **)0;
  char *fname, *path;
  int numbadfiles = 0, dir_lth, err = 0, ffd, tmp; 

  if (diff_objid(&rp->content.signedData.encapContentInfo.eContentType, 
    id_roa_pki_manifest)) return ERR_SCM_BADCT;
  if (dirp && *dirp) 
    {
    dir_lth = strlen(dirp) + 1;
    if (dirp[dir_lth - 2] == '/') dir_lth--;
    }
  else dir_lth = 0;
  certp = (struct Certificate *)member_casn(&rp->content.signedData.
    certificates.self, 0);
  if ((tmp = check_sig(rp, certp)) != 0) return tmp;
  manp = &rp->content.signedData.encapContentInfo.eContent.manifest;

  path = (char *)calloc(1, dir_lth + 1);
  for (fahp = (struct FileAndHash *)member_casn(&manp->fileList.self, 0); fahp; 
    fahp = (struct FileAndHash *)next_of(&fahp->self))
    {
    int name_lth = vsize_casn(&fahp->file);
    fname = (char *)calloc(1, name_lth + 8);
    read_casn(&fahp->file, (uchar *)fname);
    path = (char *)realloc(path, dir_lth + name_lth + 4);
    if (dir_lth) strcat(strncpy(path, dirp, dir_lth), "/");
    strcat(path, fname);
    tmp = 0;
    if ((ffd = open(path, O_RDONLY)) < 0) tmp = ERR_SCM_COFILE;
    else tmp = check_fileAndHash(fahp, ffd);
    if (tmp < 0)  // add the file to the list 
      {
      if (numbadfiles == 0) 
	badfilespp = (struct badfile **)calloc(2, sizeof(struct badfile *));
      else badfilespp = (struct badfile **)realloc(badfilespp, ((numbadfiles + 1) * 
        sizeof(struct badfile *)));
      struct badfile *badfilep = (struct badfile *)calloc(1, sizeof(struct badfile));
      badfilespp[numbadfiles++] = badfilep;
      badfilep->fname = fname;
      badfilep->err = tmp;
      if (!err) err = tmp;
      }
    else free(fname);
    }
  free(path);
  *badfilesppp = badfilespp;
  return err;
  }
