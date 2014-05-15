#include "skgu.h"

/* memory for pointers is allocated, so arguments can be freed on return */
cert *
cert_init (const dckey *is, const char *id, const dckey *pub, 
	   unsigned int ndays)
{
  cert *res = NULL;

  /* identities cannot contain commas ',' */
  if ((is) && dcispriv (is) && (id) && (!strchr(id, ',')) && (pub)) {
    res = (cert *) xmalloc (sizeof (cert));

    res->version = xstrdup (CERT_VER);
    res->issuer = dckeydup (is);
    res->identity = xstrdup (id);
    res->public_key = dckeydup (pub);
    res->day_issued = time (NULL);
    /* notice that res->day_expires == res->day_issue iff ndays == 0 */ 
    res->day_expires = (time_t) (((unsigned long int) res->day_issued) 
				 + (ndays * SECS_PER_DAY));
    res->sig = NULL;
  }

  return res;
}

/* memory for pointers is allocated, so can call cert_clr (c) on return */
cert *
cert_dup (const cert *c)
{
  char *raw_res = cert_export (c, 1); /* include signature if present */
  cert *res = raw_res ? cert_import (raw_res) : NULL;

  return res;
}

char *
cert_export (const cert *c, int with_sig)
{
  char *res = NULL;

  if (!c || cat_str (&res, c->version)
      || cat_str (&res, ":ca=(")
      || cat_str (&res, dcexport_pub (c->issuer))
      || cat_str (&res, "),id=")
      || cat_str (&res, c->identity)
      || cat_str (&res, ",pk=(")
      || cat_str (&res, dcexport_pub (c->public_key))
      || cat_str (&res, "),issued=")
      || cat_str (&res, ctime (&(c->day_issued)))
      || (res[strlen(res) - 1] = ',',     /* replace '\n' by ',' */
	  cat_str (&res, "expires="))
      || cat_str (&res, ((c->day_expires == c->day_issued) ? "NEVER\n" 
			 : ctime (&(c->day_expires))))
      /* this one always eval to false; done just to remove trailing '\n' */
      || (res [strlen (res) - 1] = ((with_sig && c->sig) ? ',' : '\0'), 0)
      || (with_sig && c->sig && (cat_str (&res, "sig=") 
				 || cat_str (&res, c->sig)))) {
    xfree (res);
    res = NULL;
  }

  return res;
}

int
month_to_num (const char month[])
{
  switch (month[0]) {
  case 'J':
    switch (month[1]) {
    case 'a':
      return (month[2] == 'n') ? 0 : -1;
    case 'u':
      return (month[2] == 'n') ? 5 : ((month[2] == 'l') ? 6 : -1);
    default:
      return -1;
    }
  case 'M':
    return ((month[1] != 'a') || ((month[2] !=  'r') && (month[2] !=  'y'))) ? 
      -1 : ((month[2] ==  'r') ? 2 : 4);
  case 'A':
    switch (month[1]) {
    case 'p':
      return (month[2] == 'r') ? 3 : -1;
    case 'u':
      return (month[2] == 'g') ? 7 : -1;
    default:
      return -1;
    }
  case 'F':
    return ((month[1] == 'e') && (month[2] == 'b')) ? 1 : -1;
  case 'S':
    return ((month[1] == 'e') && (month[2] == 't')) ? 8 : -1;
  case 'O':
    return ((month[1] == 'c') && (month[2] == 't')) ? 9 : -1;
  case 'N':
    return ((month[1] == 'o') && (month[2] == 'v')) ? 10 : -1;
  case 'D':
    return ((month[1] == 'e') && (month[2] == 'c')) ? 11 : -1;
  default: 
    return -1;
  }
}

int
asc_to_num (const char *d, unsigned int l)
{
  unsigned int i;
  int diff, res = 0;

  for (i = 0; i < l; i++) {
    /* skip leading blanks */
    if ((d[i] == ' ') || (d[i] == '\t'))
      continue;
    else {
      diff = d[i] - '0';
      if ((diff >= 0) && (diff <= 9))
	res = 10 * res + diff;
      else
	return -1;
    }
  }

  return res;
}

time_t
parse_date (const char **a)
{
  const char *d = *a;
  struct tm raw_time;

  if (skip_str (&d, "Mon ") && skip_str (&d, "Tue ") && skip_str (&d, "Wed ") 
      && skip_str (&d, "Thu ") && skip_str (&d, "Fri ") 
      && skip_str (&d, "Sat ") && skip_str (&d, "Sun ")) {
    return (time_t)-1;
  }

  /* now get the month */
  if (((raw_time.tm_mon = month_to_num (d)) == -1) || (d[3] != ' ')) {
    return (time_t)-1;
  }
  d += 4;

  /* ... the day */
  if (((raw_time.tm_mday = asc_to_num (d, 2)) == -1) || (d[2] != ' ')) {
    return (time_t)-1;
  }
  d += 3;

  /* ... the hours */
  if (((raw_time.tm_hour = asc_to_num (d, 2)) == -1) || (d[2] != ':')) {
    return (time_t)-1;
  }
  d += 3;

  /* ... the minutes */
  if (((raw_time.tm_min = asc_to_num (d, 2)) == -1) || (d[2] != ':')) {
    return (time_t)-1;
  }
  d += 3;

  /* ... the seconds */
  if (((raw_time.tm_sec = asc_to_num (d, 2)) == -1) || (d[2] != ' ')) {
    return (time_t)-1;
  }
  d += 3;

  /* ... and the year */
  if (((raw_time.tm_year = asc_to_num (d, 4)) == -1)) {
    return (time_t)-1;
  }
  d += 4;
  raw_time.tm_year -= 1900;
  raw_time.tm_isdst = -1;
  
  *a = d;
  return mktime (&raw_time);
}

void
cert_clr (cert *c)
{
  if (c) {
    check_n_free (&(c->version));
    check_n_free_key (&(c->issuer));
    check_n_free (&(c->identity));
    check_n_free_key (&(c->public_key));
    
    xfree (c);
  }
}

cert *
cert_import (const char *asc)
{
  cert *c = NULL;
  const char *saved_asc;
  char *p = NULL;

  /* first find the version string */ 
  if (skip_str (&asc, CERT_VER)
      || skip_str (&asc, ":ca=("))
    return NULL;

  c = (cert *) xmalloc (sizeof (cert));
  c->version = xstrdup (CERT_VER);
  c->issuer = c->public_key = NULL;
  c->identity = c->sig = NULL;

  /* now find the issuer's public key, which is terminated by ")," */
  saved_asc = asc;
  if (!(asc = strchr (asc, ')')) || skip_str (&asc, "),id=")) {
    cert_clr (c);
    return  NULL;
  }

  /* copy the portion from saved_asc to asc - 6 into a temporary buffer */
  p = (char *) xmalloc (asc - 6 - saved_asc + 2); /* extra byte for '\0' */
  strncpy (p, saved_asc, asc - 6 - saved_asc + 1);
  p[asc - 6 - saved_asc + 1] = '\0'; 

  /* import the issuer's public key from this buffer */
  if (!(c->issuer = dcimport_pub (p))) {
    xfree (p);
    cert_clr(c);
    return  NULL;
  }
  xfree (p);
  p = NULL;

  /* now read the identity by looking at the next "," */
  saved_asc = asc;
  if (!(asc = strchr (asc, ',')) || skip_str (&asc, ",pk=(")) {
    cert_clr (c);
    return  NULL;
  }

  /* the portion from saved_asc to asc - 6 is the certified identity */
  c->identity = (char *) xmalloc (asc - 6 - saved_asc + 2);
  strncpy (c->identity, saved_asc, asc - 6 - saved_asc + 1);
  (c->identity)[asc - 6 - saved_asc + 1] = '\0';

  /* now find the certified public key, which is again terminated by ")," */
  saved_asc = asc;
  if (!(asc = strchr (asc, ')')) || skip_str (&asc, "),issued=")) {
    cert_clr (c);
    return  NULL;
  }

  /* copy the portion from saved_asc to asc - 10 into a temporary buffer */
  p = (char *) xmalloc (asc - 10 - saved_asc + 2);
  strncpy (p, saved_asc, asc - 10 - saved_asc + 1);
  p[asc - 10 - saved_asc + 1] = '\0'; 

  /* import the certified public key from this buffer */
  if (!(c->public_key = dcimport_pub (p))) {
    xfree (p);
    cert_clr(c);
    return  NULL;
  }
  xfree (p);
  p = NULL;

  /* now read the day this certificate was issued  */
  if (((c->day_issued = parse_date (&asc)) == -1) 
      || skip_str (&asc, ",expires=")) {
    cert_clr (c);
    return NULL;
  }

  /* now read the expiration date */
  if (!strcmp (asc, "NEVER")) {
    c->day_expires = c->day_issued;
  }
  else if (((c->day_expires = parse_date (&asc)) == -1) 
	   || skip_str (&asc, ",sig=")) {
    cert_clr (c);
    return NULL;
  }
	   
  /* finally, copy the signature */
  c->sig = xstrdup (asc);

  return c;
}

/* prepares a certificate, signs it and writes it to file */
int 
cert_sign_n_write (const dckey *ca, const char *id, const dckey *pub, 
		   unsigned int ndays, const char *cert_file)
{
  int fdcert;
  cert *cert = NULL; 
  char *cert_msg = NULL;
  
  if (!(cert = cert_init (ca, id, pub, ndays))
      || !(cert_msg = cert_export (cert, 0))
      || !(cert->sig = dcsign (ca, cert_msg))
      || (xfree (cert_msg), !(cert_msg = cert_export (cert, 1)))) {
    printf ("%s: error creating the certificate\n", getprogname ());
    cert_clr (cert);
    cert = NULL;
    check_n_free (&cert_msg);
    
    return -2;
  }
  /* write certificate and signature to fdcert */
  else {
    if ((fdcert = open (cert_file,O_WRONLY|O_TRUNC|O_CREAT,0644)) == -1){
      printf ("%s: trouble opening %s\n",
	      getprogname (), cert_file);
      perror (getprogname ());

      cert_clr (cert);
      cert = NULL;
      check_n_free (&cert_msg);
      
      return -1;
    }
    else if ((write_chunk (fdcert, cert_msg, strlen (cert_msg)) == -1) 
	     || (write_chunk (fdcert, "\n", 1) == -1)) {
      printf ("%s: trouble writing certificate to %s\n",
	      getprogname (), cert_file);
      perror (getprogname ());

      cert_clr (cert);
      cert = NULL;
      check_n_free (&cert_msg);
      
      return -1;
    }
    else {
      cert_clr (cert);
      cert = NULL;
      check_n_free (&cert_msg);
      
      close (fdcert);
      fdcert = -1;
      
      return 0;
    }
  }
}

/* reads a certificate from file */
/* on error  yields NULL; o/w returns a cert */
cert *
cert_read (const char *cert_file) 
{
  int fdcert = open (cert_file, O_RDONLY);
  char *raw_cert = (fdcert == -1) ? NULL : import_from_file (fdcert);
  cert *c = raw_cert ? cert_import (raw_cert) : NULL;  

  return c;
}

/* verify the signature on a certificate */
int
cert_verify (const cert *c)
{
  int res;

  char *raw_cert = cert_export (c, 0); /* don't append sig to cert */
  
  if (!raw_cert || (dcverify (c->issuer, raw_cert, c->sig) == -1)
      || ((c->day_issued != c->day_expires) 
	  && (difftime (c->day_expires, time (NULL)) < -EXP_CERT_GRACE))) {
    res = 0;
  }
  else {
    res = 1;
  }

  check_n_free (&raw_cert);

  return res;
}
