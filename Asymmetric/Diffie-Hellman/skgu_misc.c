#include "skgu.h"

/* Verify the validity of a certificate */
cert *
pki_check(char *cert_file, char *pub_file, char *id)
{
  cert *c = cert_read (cert_file);
  dckey *pub = pub_from_file (pub_file);

  if (!c) {
    printf ("Error reading the certificate from %s\n", cert_file);
    
    exit (-1);
  }

  if (!pub) {
    printf ("Error reading the public key from %s\n", pub_file);
    
    exit (-1);
  }

  if (!cert_verify (c)) {
    printf ("Certificate invalid or expired\n");
    
    exit (-1);
  }

  if (!dcareequiv (c->public_key, pub)) {
    printf ("The certificate in %s does not refer to the public key in %s\n",
	    cert_file, pub_file);
    
    exit (1);
  }
  
  if (strcmp (c->identity, id) != 0) {
    printf ("The certificate in %s does not refer to identity %s\n",
	    cert_file, id);
    
    exit (1);
  }

  /* everything checked out */
  printf ("Valid certificate\n");

  dcfree (pub);
  
  return c;
}

void
write_pubfile (const char *pubfname, dckey *priv)
{
  int fdpub;
  char *p;
  int status;

  if (!(p = dcexport_pub (priv))) {
    printf ("%s: trouble exporting public part from a private key\n", 
	     getprogname ());
    
    dcfree (priv);

    exit (-1);
  }
  else if ((fdpub = open (pubfname, O_WRONLY|O_TRUNC|O_CREAT, 0644)) == -1) {
    perror (getprogname ());
    free (p);
    dcfree (priv);

    exit (-1);
  }
  else {
    status = write (fdpub, p, strlen (p));
    if (status != -1) {
      status = write (fdpub, "\n", 1);
    }
    free (p);
    close (fdpub);
    /* do not dcfree priv under normal circumstances */ 

    if (status == -1) {
      printf ("%s: trouble writing public key to file %s\n", 
	       getprogname (), pubfname);
      perror (getprogname ());
      
      dcfree (priv);

      exit (-1);
    }
  }
}

void
write_privfile (const char *privfname, dckey *priv)
{
  int fdpriv;
  char *s;
  int status;

  if (!(s = dcexport_priv (priv))) {
    printf ("%s: trouble exporting private key\n", getprogname ());
    
    dcfree (priv);

    exit (-1);
  }
  else if ((fdpriv = open (privfname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());
    free (s);
    dcfree (priv);

    exit (-1);
  }
  else {
    status = write (fdpriv, s, strlen (s));
    if (status != -1) {
      status = write (fdpriv, "\n", 1);
    }
    free (s);
    close (fdpriv);
    /* do not dcfree priv under normal circumstances */ 

    if (status == -1) {
      printf ("%s: trouble writing private key to file %s\n", 
	      getprogname (), privfname);
      perror (getprogname ());
      
      dcfree (priv);
      
      exit (-1);
    }
  }
}

dckey *
import_pub_from_file (int fdpub)
{
  char *pretty_key = import_from_file (fdpub);
  dckey *key = dcimport_pub (pretty_key);

  free (pretty_key);
  close (fdpub);

  if (!key) {
    printf ("%s: trouble importing key from file\n",
	    getprogname ());
   
    exit (-1);
  }


  return key;
}

dckey *
import_priv_from_file (int fdpriv)
{
  char *pretty_key = import_from_file (fdpriv);
  dckey *key = dcimport_priv (pretty_key);

  free (pretty_key);
  close (fdpriv);

  if (!key) {
    printf ("%s: trouble importing key from file\n",
	    getprogname ());
   
    exit (-1);
  }

  return key;
}

dckey *
priv_from_file (const char *fn)
{
  dckey *priv = NULL;
  int fdpriv = open (fn, O_RDONLY); 

  if (fdpriv == -1) {
    perror (getprogname ());
      
    exit (1);
  }
  else {
    if (!(priv = import_priv_from_file (fdpriv))) {
      printf ("%s: no private key found in %s\n", getprogname (), fn);
      
      close (fdpriv);
      exit (-1);
    }
    close (fdpriv);
  }
  
  return priv;
}

dckey *
pub_from_file (const char *fn)
{
  dckey *pub = NULL;
  int fdpub = open (fn, O_RDONLY); 
  
  if (fdpub == -1) {
    perror (getprogname ());
      
    exit (1);
  }
  else {
    if (!(pub = import_pub_from_file (fdpub))) {
      printf ("%s: no public key found in %s\n", getprogname (), fn);
      
      close (fdpub);
      exit (-1);
    }
    close (fdpub);
  }
  
  return pub;
}

char
hex_nibble (u_char _nib) 
{
  u_char nib = (_nib & 0x0f);

  return ((nib < 10) ? ('0' + nib) : ('a' + nib - 10));
}

int
cat_buf (char **dstp, const void *buf, size_t len)
{
  const u_char *_buf = (const u_char *) buf;
  char *str = (char *) xmalloc (2 * len + 3);
  size_t i, j;
  int res;

  str[0] = '0';
  str[1] = 'x';
  for (i = 0, j = 2; i < len ; i++) {
    str[j++] = hex_nibble ((_buf[i] & 0xf0) >> 4);
    str[j++] = hex_nibble (_buf[i] & 0x0f);
  }

  str[j] = '\0';

  res = cat_str (dstp, str);
  free (str);
  return res;
}

void check_n_free(char **a) 
{
  if (a && (*a)) { 
    xfree (*a); 
    *a = NULL;
  }
}

void check_n_free_key(dckey **k) 
{
  if (k && (*k)) { 
    dcfree (*k); 
    *k = NULL;
  }
}
