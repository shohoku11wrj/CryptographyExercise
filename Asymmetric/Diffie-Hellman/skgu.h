#ifndef _SKGU_H_
#define _SKGU_H_

#include "dcrypt.h"
#include "pv.h"

#define CERT_VER "SKGU-Cert-1"
#define SECS_PER_DAY (60 * 60 * 24)
#define EXP_CERT_GRACE (60 * 60) /* grace period (in secs) for expired certs */

/* XXX this char * constant comes from elgamal.c internals */
#define ELGAMAL_STR "Elgamal-1"

struct cert {
  char *version;
  dckey *issuer;
  char *identity;
  dckey *public_key;
  time_t day_issued;
  time_t day_expires;
  char *sig;
};
typedef struct cert cert;

/* skgu_misc.c */
char *import_from_file (int fpub);
dckey *import_pub_from_file (int fdpub);
dckey *import_priv_from_file (int fdpub);
dckey *priv_from_file (const char *fn);
dckey *pub_from_file (const char *fn);
void write_pubfile (const char *pubfname, dckey *priv);
void write_privfile (const char *privfname, dckey *priv);
int cat_buf (char **dstp, const void *buf, size_t len);
void check_n_free(char **a);
void check_n_free_key(dckey **k);
/* ADDED by rweng */
char hex_nibble (u_char _nib);

/* skgu_cert.c */
cert *pki_check(char *cert_file, char *pub_file, char *id);
/* memory for pointers is allocated, so arguments can be freed on return */
cert *cert_init (const dckey *is, const char *id, const dckey *pk,
                 unsigned int ndays);
cert *cert_dup (const cert *c);
char *cert_export (const cert *c, int with_sig);
int month_to_num (const char month[]);
int asc_to_num (const char *d, unsigned int l);
time_t parse_date (const char **a);
void cert_clr (cert *c);
cert *cert_import (const char *asc);
int cert_sign_n_write (const dckey *ca, const char *id, const dckey *pk,
                       unsigned int ndays, const char *cert_file);
cert *cert_read (const char *cert_file);
int cert_verify (const cert *cert);

#endif /* _SKGU_H_ */

