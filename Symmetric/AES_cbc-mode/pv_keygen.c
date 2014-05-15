#include "pv.h"

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

void 
usage (const char *pname)
{
  printf ("Personal Vault: Symmetric Key Generation\n");
  printf ("Usage: %s SK-FILE \n", pname);
  printf ("       Generates a new symmetric key, and writes it to\n");
  printf ("       SK-FILE.  Overwrites previous file content, if any.\n");
  exit (1);
}

int 
main (int argc, char **argv)
{
  /* YOUR CODE HERE */
  char *sk_buf = NULL; /* contains *two* symmetric keys */
  const size_t sk_len = CCA_STRENGTH * 2;

  if (argc != 2) {
    usage (argv[0]);
  }
  else {
    setprogname (argv[0]);

    /* first, let's create a new symmetric key */
    ri ();

    /* Note that since we'll need to do both AES-CBC-MAC and HMAC-SHA1,
       there are actuall *two* symmetric keys, which could, e.g., be 
       stored contiguosly in a buffer */

    /* YOUR CODE HERE */
    sk_buf = (char *) malloc (sk_len * sizeof (char));
    prng_getbytes (sk_buf, sk_len);

    /* now let's armor and dump to disk the symmetric key buffer */

    /* YOUR CODE HERE */
    write_skfile (argv[1], sk_buf, sk_len);

    /* finally, let's scrub the buffer that held the random bits 
       by overwriting with a bunch of 0's */
    bzero (sk_buf, sk_len);
    free (sk_buf);
  }

  return 0;
}

