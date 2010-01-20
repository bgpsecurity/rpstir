#include <stdio.h>
#include "roa_utils.h"
#include "cryptlib.h"

/* $Id: test_manifest.c 453 2007-07-25 15:30:40Z mreynolds $ */

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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

void free_badfiles(struct badfile **badfilespp)
  {  // for rsync_aur or anyone else who calls manifestValidate2
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
  struct badfile **badfilespp = (struct badfile **)0;
  char *fname, *path;
  int numbadfiles = 0, dir_lth, err = 0, ffd, tmp;
       // do general checks including signature if cert is present
  if ((err = cmsValidate(rp)) < 0) return err;
     // certificate check
  if (num_items(&rp->content.signedData.certificates.self) != 1) 
    return ERR_SCM_BADNUMCERTS;
      // other specific manifest checks
  if (diff_objid(&rp->content.signedData.encapContentInfo.eContentType,
    id_roa_pki_manifest)) return ERR_SCM_BADCT;
  manp = &rp->content.signedData.encapContentInfo.eContent.manifest;
  ulong mlo, mhi;
  if (read_casn_time(&manp->thisUpdate, &mlo) <= 0 ||
      read_casn_time(&manp->nextUpdate, &mhi) <= 0 ||
      mlo >= mhi) return ERR_SCM_BADDATES;
      // all checks done.  Get to the details
  if (dirp && *dirp)
    {
    dir_lth = strlen(dirp) + 1;
    if (dirp[dir_lth - 2] == '/') dir_lth--;
    }
  else dir_lth = 0;
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
    else tmp = check_fileAndHash(fahp, ffd, NULL, 0, 0);
    (void)close(ffd);
    if (tmp < 0)  // add the file to the list
      {
      if (numbadfiles == 0)
	badfilespp = (struct badfile **)calloc(2, sizeof(struct badfile *));
      else badfilespp = (struct badfile **)realloc(badfilespp, ((numbadfiles + 2) *
        sizeof(struct badfile *)));
      struct badfile *badfilep = (struct badfile *)calloc(1, sizeof(struct badfile));
      badfilespp[numbadfiles++] = badfilep;
      badfilespp[numbadfiles] = (struct badfile *)0;
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

int main(int argc, char **argv)
{
  struct ROA roa;
  struct Certificate *certp;
  char *dirp;
  struct badfile **badfilespp;
  int err;

  ROA(&roa, 0);
  if (argc < 2) {
      fprintf(stderr, "usage: %s directory manifest [manifest ...]\n", argv[0]);
      return 0;
  }
  argv++;
  dirp = *argv++;
  for (; *argv != NULL; argv++) {

      /* read and decode the file */
      if (get_casn_file(&roa.self, *argv, 0) != 0) {
	  fprintf(stderr, "Reading roa failed\n");
	  continue;
      }

      /* XXX we get this but never do anything with it */
      certp = (struct Certificate *)
	  member_casn(&roa.content.signedData.certificates.self, 0);
      if (certp == NULL) {
          fprintf(stderr, "Couldn't get certificate in roa\n");
	  continue;
      }

      /* see if it has the right content type (manifest) */
      if (diff_objid(&roa.content.signedData.encapContentInfo.eContentType, 
		     id_roa_pki_manifest)) {
          fprintf(stderr, "%s not a manifest\n", *argv);
	  continue;
      }

      /* validate the manifest */
      err = manifestValidate2(&roa, dirp, &badfilespp);
      fprintf(stderr, "Checking %s ", *argv);
      if (err != 0) {
	  fprintf(stderr, "failed.\n");
	  if (badfilespp != NULL) {
              fprintf(stderr,  "    Bad files were:\n");
              struct badfile **bf;
              for (bf = badfilespp; bf && *bf; bf++)
		  fprintf(stderr, "        %s\n", (*bf)->fname);
	  }
	  continue;
      }
      fprintf(stderr, "SUCCEEDED\n");
  }
  return 0;
  
