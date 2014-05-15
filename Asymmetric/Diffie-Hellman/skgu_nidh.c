#include "skgu.h"

#define DEFAULT_LABEL "skgu_key"

/* COPY from lab1 */
void
write_skfile (const char *skfname, void *raw_sk, size_t raw_sklen)
{
  int fdsk = 0;
  char *s = NULL;
  int status = 0;

  /* armor the raw symmetric key in raw_sk using armor64 */

  /* YOUR CODE HERE */
  s = (char *) malloc ( (2 * raw_sklen) * sizeof (char));
  s = armor64 (raw_sk, raw_sklen);
  ssize_t armor64_len = armor64len (s);

      if (armor64_len == -1) {

  perror (getprogname ());
  bzero (raw_sk, raw_sklen);
  free (raw_sk);
  exit (-1);

      } else {

  *(s + armor64_len) = '\0';

  /* now let's write the armored symmetric key to skfname */

  if ((fdsk = open (skfname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());
    free (s);

    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
    bzero (raw_sk, raw_sklen);
    free (raw_sk);

    exit (-1);
  }
  else {
    status = write (fdsk, s, strlen (s));
    if (status != -1) {
      status = write (fdsk, "\n", 1);
    }
    free (s);
    close (fdsk);
    /* do not scrub the key buffer under normal circumstances
       (it's up to the caller) */ 

    if (status == -1) {
      printf ("%s: trouble writing symmetric key to file %s\n", 
	      getprogname (), skfname);
      perror (getprogname ());
      
    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
      bzero (raw_sk, raw_sklen);
      free (raw_sk );
      
      exit (-1);
    }
  }
      }
}

struct rawpub {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t y;			/* g^x mod p */
};
typedef struct rawpub rawpub;

struct rawpriv {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t x;			/* x mod q */
};
typedef struct rawpriv rawpriv;

int 
get_rawpub (rawpub *rpub_ptr, dckey *pub) {
  const char *pub_as_str = (const char *) dcexport (pub);

  if (skip_str (&pub_as_str, ELGAMAL_STR)
      || skip_str (&pub_as_str, ":Pub,p="))
    return -1;

  mpz_init (rpub_ptr->p);
  mpz_init (rpub_ptr->q);
  mpz_init (rpub_ptr->g);
  mpz_init (rpub_ptr->y);

  if (read_mpz (&pub_as_str, rpub_ptr->p)
      || skip_str (&pub_as_str, ",q=")
      || read_mpz (&pub_as_str, rpub_ptr->q)
      || skip_str (&pub_as_str, ",g=")
      || read_mpz (&pub_as_str, rpub_ptr->g)
      || skip_str (&pub_as_str, ",y=")
      || read_mpz (&pub_as_str, rpub_ptr->y)) {
    return -1;
  }

  return 0;
}

int 
get_rawpriv (rawpriv *rpriv_ptr, dckey *priv) {
  const char *priv_as_str = (const char *) dcexport (priv);

  if (skip_str (&priv_as_str, ELGAMAL_STR)
      || skip_str (&priv_as_str, ":Priv,p="))
    return -1;

  mpz_init (rpriv_ptr->p);
  mpz_init (rpriv_ptr->q);
  mpz_init (rpriv_ptr->g);
  mpz_init (rpriv_ptr->x);

  if (read_mpz (&priv_as_str, rpriv_ptr->p)
      || skip_str (&priv_as_str, ",q=")
      || read_mpz (&priv_as_str, rpriv_ptr->q)
      || skip_str (&priv_as_str, ",g=")
      || read_mpz (&priv_as_str, rpriv_ptr->g)
      || skip_str (&priv_as_str, ",x=")
      || read_mpz (&priv_as_str, rpriv_ptr->x)) {
    return -1;
  }

  return 0;
}

void 
usage (const char *pname)
{
  printf ("Simple Shared-Key Generation Utility\n");
  printf ("Usage: %s PRIV-FILE PRIV-CERT PRIV-ID PUB-FILE PUB-CERT PUB-ID [LABEL]\n", pname);
  exit (-1);
}

void
nidh (dckey *priv, dckey *pub, char *priv_id, char *pub_id, char *label)
{
  rawpub rpub;
  rawpriv rpriv;

  /* YOUR VARS HERE */
  mpz_t dh_ab;  /* DH (Alice.pub, Bob.pub) */
  char *buf = NULL; /* DH(Alice.pub, Bob.pub) || fst_id || snd_id */
  char *dstp = NULL; /*!! IMPORTANT to set NULL */
  char *k_m;    /* 20 bytes */
  char *k_s0;   /* 20 bytes */
  char *k_s1;   /* 20 bytes */
  char *k_s;    /* 32 bytes */
  char *desp;
  char *desp_s0 = NULL;
  char *desp_s1 = NULL;
  int ret = -1;
  int i;
  char *dest; /* result, armor64ed shared key */

  dest = (char *) malloc ( (2 * 32) * sizeof (char) );
  k_m  = (char *) malloc ( sha1_hashsize * sizeof (char) );
  k_s0 = (char *) malloc ( 20 * sizeof (char) );
  k_s1 = (char *) malloc ( 20 * sizeof (char) );
  k_s  = (char *) malloc ( 32 * sizeof (char) );
  /* description = "MY-APP:task=encryption,opt=(sndr=alice,rcvr=bob)" , len: 40+alice+bob */
  desp = (char *) malloc ( (40 + sizeof (priv_id) + sizeof (pub_id)) * sizeof (char) );
  /*desp_s0 = (char *) malloc ( (sizeof (desp) + 7) * sizeof (char) );*/ /* desp || AES-CBC */
  /*desp_s1 = (char *) malloc ( (sizeof (desp) + 9) * sizeof (char) );*/ /* desp || HMAC-SHA1 */
  /*buf = (void *) malloc ( (sizeof (k_m) + sizeof (priv_id) + sizeof (pub_id)) * sizeof (char) );*/

  /* step 0: check that the private and public keys are compatible,
     i.e., they use the same group parameters */

  if ((-1 == get_rawpub (&rpub, pub)) 
      || (-1 == get_rawpriv (&rpriv, priv))) {
    printf ("%s: trouble importing GMP values from ElGamal-like keys\n",
	    getprogname ());

    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));

    exit (-1);    
  } else if (mpz_cmp (rpub.p, rpriv.p)
	     || mpz_cmp (rpub.q, rpriv.q)
	     || mpz_cmp (rpub.g, rpriv.g)) {
    printf ("%s:  the private and public keys are incompatible\n",
	    getprogname ());
    
    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));

    exit (-1);
  } else {
    
    /* step 1a: compute the Diffie-Hellman secret
                (use mpz_init, mpz_powm, mpz_clear; look at elgamal.c in 
                 the libdcrypt source directory for sample usage 
     */
    
    /* YOUR CODE HERE */
    /* DH (g^a mod p, g^b mod p) = g^ab mod p */
    mpz_init (dh_ab);
    mpz_powm (dh_ab, rpub.y, rpriv.x, rpub.p);

    /* allocate *dstp an ANSI-C string (a '\0'-terminated char *) */
    ret = cat_mpz (&dstp, dh_ab);
    if (ret != 0) {
      mpz_clear (dh_ab);
      printf("Error: trouble arose when allocating space for dh_ab");
      exit (-1);
    }
    
    /* step 1b: order the IDs lexicographically */
    char *fst_id = NULL, *snd_id = NULL;
    
    if (strcmp (priv_id, pub_id) < 0) {
      fst_id = priv_id;
      snd_id = pub_id;
    } else {
      fst_id = pub_id;
      snd_id = priv_id;
    }    
    
    /* step 1c: hash DH secret and ordered id pair into a master key */
    
    /* YOUR CODE HERE */
    cat_str (&buf, dstp);
    cat_str (&buf, fst_id);
    cat_str (&buf, snd_id);
    /* printf ("buf = %s\n", buf); */

    /* K_m = SHA1 ( DH(Alice.pub, Bob.pub) || first_id || second_id ) */
    /* hmac_sha1 (dstp, strlen (dstp), k_m, str_ab, strlen (str_ab)); */
    sha1_hash (k_m, buf, strlen(buf) * sizeof (char));

    /* TEST, output k_m
    char *res;
    res = (char *) malloc ((2 * sha1_hashsize + 1) * sizeof (char));
    u_int i, j;
    for (i = j = 0; i < sha1_hashsize; i++) {
      res[j++] = hex_nibble ((k_m[i] & 0xf0) >> 4);
      res[j++] = hex_nibble (k_m[i] & 0x0f);
    }
    res[j] = '\0';
    printf ("k_m = %s\n", res);
    */

    /* step 2: derive the shared key from the label and the master key */
    /* K_s0 = HMAC-SHA1 ( k_m, description || "AES-CBC" ) 
       K_s1 = HMAC-SHA1 ( k_m, description || "HMAC-SHA1" )
       K_s  = < concatenation of first 16 bytes of K_s0 ||
                                 first 16 bytes of K_s1 >
       description = "MY-APP:task=encryption,opt=(sndr=alice,rcvr=bob)"
     */
    
    /* YOUR CODE HERE */
    sprintf (desp, "MY-APP:task=encryption,opt=(sndr=%s,rcvr=%s)", fst_id, snd_id);
    cat_str (&desp_s0, desp);
    cat_str (&desp_s0, "AES-CBC");
    cat_str (&desp_s1, desp);
    cat_str (&desp_s1, "HMAC-SHA1");
    /*
    printf ("desp: %s\n", desp);
    printf ("desp_s0: %s\n", desp_s0);
    printf ("desp_s1: %s\n", desp_s1);
    */

    /* void hmac_sha1 (const char *key, size_t keylen, void *out, const void *data, size_t dlen);
     Computes the HMAC over len bytes of data at buf using the key key, and places the resulting 20 bytes at out. */
    hmac_sha1 (k_m, sha1_hashsize, k_s0, desp_s0, strlen (desp_s0));
    hmac_sha1 (k_m, sha1_hashsize, k_s1, desp_s1, strlen (desp_s1));

    /* TEST , output k_s0 & k_s1
    for (i = j = 0; i < sha1_hashsize; i++) {
      res[j++] = hex_nibble ((k_s0[i] & 0xf0) >> 4);
      res[j++] = hex_nibble (k_s0[i] & 0x0f);
    }
    res[j] = '\0';
    printf ("k_s0 = %s\n", res);
    for (i = j = 0; i < sha1_hashsize; i++) {
      res[j++] = hex_nibble ((k_s1[i] & 0xf0) >> 4);
      res[j++] = hex_nibble (k_s1[i] & 0x0f);
    }
    res[j] = '\0';
    printf ("k_s1 = %s\n", res);
    */

    for (i = 0; i < 16; i++) {
      *(k_s + i) = *(k_s0 + i);
      *(k_s + 16 + i) = *(k_s1 + i);
    }
    *(k_s + 32) = '\0';
    
    /* TEST , output k_s
    for (i = j = 0; i < sha1_hashsize; i++) {
      res[j++] = hex_nibble ((k_s[i] & 0xf0) >> 4);
      res[j++] = hex_nibble (k_s[i] & 0x0f);
    }
    res[j] = '\0';
    printf ("k_s = %s\n", res);
    */
    
    /* step 3: armor the shared key and write it to file.
       Filename should be of the form <label>-<priv_id>.b64 */
    
    /* YOUR CODE HERE */
    dest = armor64 (k_s, 32);
    printf ("shared key: %s\n", dest);
    
    dest = (char *) realloc (dest, sizeof (label) + 1 + sizeof (priv_id) + 4 );
    bzero (dest, sizeof (dest));
    cat_str (&dest, label);
    cat_str (&dest, "-");
    cat_str (&dest, priv_id);
    cat_str (&dest, ".b64");
    write_skfile (dest, k_s, 32);

    /* DELETE FOLLOWING LINES WHEN YOU ARE DONE */
    /*
    printf ("\n    ----    \n");
    printf ("NOT YET IMPLEMENTED.\n");
    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));
    printf ("priv_id: %s\n", priv_id);
    printf ("pub_id: %s\n", pub_id);
    printf ("fst_id: %s\n", fst_id);
    printf ("snd_id: %s\n", snd_id);
    printf ("label: %s\n", label);
    exit (-1);
    */

    /* ADDED by rweng: clear memory cache */

    bzero (k_m, sha1_hashsize);
    bzero (k_s0, sha1_hashsize);
    bzero (k_s1, sha1_hashsize);
    bzero (k_s, 32);
    mpz_clear (rpriv.x);
    mpz_clear (dh_ab);
    bzero (buf, sizeof (buf));
    bzero (dstp, sizeof (dstp));
    bzero (dest, sizeof (dest));

    free (k_m);
    free (k_s0);
    free (k_s1);
    free (k_s);
    free (buf);
    free (dstp);
    free (dest);
  }
}

int
main (int argc, char **argv)
{
  int arg_idx = 0;
  char *privcert_file = NULL;
  char *pubcert_file = NULL;
  char *priv_file = NULL;
  char *pub_file = NULL;
  char *priv_id = NULL;
  char *pub_id = NULL;
  char *label = DEFAULT_LABEL;
  dckey *priv = NULL;
  dckey *pub = NULL;
  cert *priv_cert = NULL;
  cert *pub_cert = NULL;

  if ((7 > argc) || (8 < argc))    usage (argv[0]);

  ri ();

  priv_file = argv[++arg_idx];
  privcert_file = argv[++arg_idx];
  priv_id = argv[++arg_idx];
  pub_file  = argv[++arg_idx];
  pubcert_file = argv[++arg_idx];
  pub_id = argv[++arg_idx];
  if (argc - 2 == arg_idx) {
    /* there was a label */
    label = argv[++arg_idx];
  }

  pub_cert = pki_check(pubcert_file, pub_file, pub_id);
  /* check above won't return if something was wrong */
  pub = pub_cert->public_key;

  if (!cert_verify (priv_cert = cert_read (privcert_file))) {
      printf ("%s: trouble reading certificate from %s, "
	      "or certificate expired\n", getprogname (), privcert_file);
      perror (getprogname ());

      exit (-1);
  } else if (!dcareequiv(pub_cert->issuer,priv_cert->issuer)) {
    printf ("%s: certificates issued by different CAs.\n",
	    getprogname ());
    printf ("\tOwn (%s's) certificate in %s\n", priv_id, privcert_file);
    printf ("\tOther (%s's) certificate in %s\n", pub_id, pubcert_file);
  } else {
    priv = priv_from_file (priv_file);
    
    nidh (priv, pub, priv_id, pub_id, label);
  }

  return 0;
}
