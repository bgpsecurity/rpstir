#include "conversion.h"

char *msgs[] = {
    "Finished %s OK\n",
    "Too %s parameters\n",    // 1
    "Invalid line: %s",
    "Duplicate SKI: %s ",       // 3
    "Missing %s line\n",
    "Premature end of file\n",  // 5
    "overlap at: %s",
    "Can't open %s\n",          // 7
    "Had warnings.  New file NOT created\n",
    };

int warnings;

static void warn (int err, char *paramp)
  {
  fprintf(stderr, msgs[err], paramp);
  if (err) warnings++;
  }

static void fatal(int err, char *paramp)
  {
  warn(err, paramp);
  if(err) warn(8, "");
  exit(0);
  }

static int sort_resources(struct iprange *iprangesp, int numranges)
  {
  struct iprange *rp0, *rp1, spare;
  int did, i;
  for (did = 0, i = 1; i < numranges; )
    {
    rp0 = &iprangesp[i - 1];
    rp1 = &iprangesp[i];
    if (diff_ipaddr(rp0, rp1) > 0) // swap them
      {
      memcpy(&spare, rp0, sizeof(struct iprange));
      memcpy(rp0, rp1,    sizeof(struct iprange));
      memcpy(rp1, &spare, sizeof(struct iprange));
      i = 1;    // go back to start
      did++;
      }
    else i++;
    }
  return did;
  } 

static void process_type(FILE *str, FILE *tmpstr, int typ, char *inbuf, 
  char *ending)
  {
  int numranges;
  struct iprange *iprangesp = (struct iprange *)0; 
  char locbuf[80];  
  strcpy(locbuf, inbuf);
  for (numranges = 0; strncmp(locbuf, ending, strlen(ending)); numranges++)
    {
    if (!numranges) iprangesp = (struct iprange *)calloc(1, 
      sizeof(struct iprange));
    else iprangesp = (struct iprange *)realloc(iprangesp, 
      (sizeof(struct iprange) * (numranges + 1)));
    struct iprange *tiprangep = &iprangesp[numranges];
    if (txt2loc(typ, locbuf, tiprangep) < 0) 
      {
      warn(2, locbuf);
      numranges--;    // scrub the entry
      }
    else if (numranges > 0 /* haven't incremented it yet */ && 
      overlap(&iprangesp[numranges - 1], &iprangesp[numranges]))
      warn(6, locbuf);
    tiprangep->text = (char *)calloc(1, strlen(locbuf) + 2);
    strcpy(tiprangep->text, locbuf);
          // get the next one
    if (!fgets(locbuf, sizeof(locbuf), str))
      {
      if (strcmp(ending, "SKI ")) fatal(5, "");
      else 
        {
        *locbuf = (char)0;
        numranges++; // have to count last one
        break;
        }
      }
    }
  strcpy(inbuf, locbuf);
  sort_resources(iprangesp, numranges);
  int i;
  for (i = 0; i < numranges; i++) fprintf(tmpstr, iprangesp[i].text);
  free(iprangesp);
  }

int main(int argc, char **argv)
  {
  char **skis, inbuf[128];
  int numskis = 0;
  if (argc != 2) fatal(1, (argc < 1)? "few": "many");
  FILE *str = fopen(argv[1], "r");
  if (!str) fatal(7, argv[1]);
  FILE *tmpstr;
  char *f = "xproof.tmp";
  if (!(tmpstr = fopen(f, "w+"))) fatal(7, f);
  if (!fgets(inbuf, sizeof(inbuf), str) ||
    strncmp(inbuf, "RP_Key ", 6)) fatal(2, inbuf); 
  fputs(inbuf, tmpstr);
  if (!fgets(inbuf, sizeof(inbuf), str) ||
    strncmp(inbuf, "SKI ", 4)) fatal(2, inbuf);
  
  char *c;
  do    // starting with first SKI line
    {
    for (c = &inbuf[5]; *c && ((*c >= '0' && *c <= '9') ||
      (*c >= 'A' && *c <= 'F') || (*c >= 'a' && *c <= 'f')); c++);
    if (c != &inbuf[44] && *c != '\n') fatal(2, inbuf); 
    if (numskis)
      {
      int num;
      for (num = 0; num < numskis && strcmp(inbuf, skis[num]); num++);
      if (num < numskis) fatal(3, &inbuf[4]);
      }
    if (!numskis) skis = (char **)calloc(2, sizeof(char *));
    else skis = (char **)realloc(skis, (sizeof(char *) * (numskis + 2)));
    skis[numskis] = calloc(1, strlen(inbuf) + 2);
    strcpy(skis[numskis], inbuf); 
    numskis++;
    fputs(inbuf, tmpstr);
             // get IPv4 start
    if (!fgets(inbuf, sizeof(inbuf), str)) fatal(5, "");
    if (strcmp(inbuf, "IPv4\n")) fatal(4, "IPv4");
    fputs(inbuf, tmpstr);   // print v4 hdr
            // get first v4 line, if any
    if (!fgets(inbuf, sizeof(inbuf), str)) fatal(5, "");
            // process v4 entries, if any
    process_type(str, tmpstr, 4, inbuf, "IPv6\n");
    fputs(inbuf, tmpstr);    // print v6 hdr
            // get first v6 line, if any
    if (!fgets(inbuf, sizeof(inbuf), str)) fatal(5, "");
    process_type(str, tmpstr, 6, inbuf, "AS#\n");      
    fputs(inbuf, tmpstr);    // print as# hdr
           // get first AS#, if any
    if (!(c = fgets(inbuf, sizeof(inbuf), str))) break; 
    process_type(str, tmpstr, -1, inbuf, "SKI ");
    }
  while(*inbuf);
  if (warnings) fatal(8, "");
  char oldfile[128];
  strcat(strcpy(oldfile, argv[1]), "~");
    // rename file in argv[1] tp same name with suffixed tilde 
  unlink(oldfile);
  link(argv[1], oldfile);
    // rename tmp file to argv[1]
  unlink(argv[1]);
  link(f, argv[1]);
  unlink(f);
  fatal(0, argv[1]);
  return 0;
  }
   
      
    
