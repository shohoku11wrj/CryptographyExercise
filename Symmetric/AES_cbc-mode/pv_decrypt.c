#include "pv.h"

void
decrypt_file (const char *ptxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /*************************************************************************** 
   * Task: Read the ciphertext from the file descriptor fin, decrypt it using
   *       sk, and place the resulting plaintext in a file named ptxt_fname.
   *
   * This procedure basically `undoes' the operations performed by edu_encrypt;
   * it expects a ciphertext featuring the following structure (please refer 
   * to the comments in edu_encrypt.c for more details):
   *
   *
   *         +----+----------------------+--------+
   *         |  Y | HSHA-1 (K_HSHA-1, Y) | padlen |
   *         +----+----------------------+--------+
   *
   * where Y = CBC-AES (K_AES, {plaintext, 0^padlen})
   *       padlen = no. of zero-bytes added to the plaintext to make its
   *                length a multiple of 16.
   * 
   * Moreover, the length of Y (in bytes) is a multiple of 16, the hash value 
   * HSHA-1 (K_HSHA-1, Y) is 20-byte-long, and padlen is a sigle byte.
   * 
   * Reading Y (and then the mac and the pad length) it's a bit tricky: 
   * below we sketch one possible approach, but you are free to implement 
   * this as you wish.
   *
   * The idea is based on the fact that the ciphertext files ends with 
   * 21 bytes (i.e., sha1_hashsize + 1) used up by the HSHA-1 mac and by the 
   * pad length.  Thus, we will repeatedly attempt to perform `long read' of 
   * (aes_blocklen + sha1_hashsize + 2) bytes: once we get at the end of the 
   * ciphertext and only the last chunk of Y has to be read, such `long read'
   * will encounter the end-of-file, at which point we will know where Y ends,
   * and how to finish reading the last bytes of the ciphertext.
   */

  int fdptxt; /* file descriptor ciphertext file */
  int status, padlen = 0;
  size_t i, cur_bytes_read;
  char *iv; /* hold the IV */
  aes_ctx *sk_aes;
  sha1_ctx *sk_sha;
  size_t block_length = CCA_STRENGTH;
  char *block_buf, *dcrypt_buf;
  u_char *hmac_old, *hmac_new;
  int hash_eql;
  off_t lshift_len;

  /* use the first part of the symmetric key for the CBC-AES decryption ...*/
  /* ... and the second for the HMAC-SHA1 */
  sk_aes = (aes_ctx *) malloc (sizeof (aes_ctx));
  aes_setkey (sk_aes, (void *) raw_sk, block_length);

  sk_sha = (sha1_ctx *) malloc (sizeof (sha1_ctx));
	hmac_sha1_init((char *) raw_sk + block_length, block_length, sk_sha);

  /* Reading Y */

  /* First, read the IV (Initialization Vector) */
  iv = (char *) malloc (block_length * sizeof (char));
  block_buf = (char *) malloc ( (block_length + sha1_hashsize + 2) * sizeof (char));
  dcrypt_buf = (char *) malloc (block_length * sizeof (char));
  hmac_old = (u_char *) malloc (sha1_hashsize * sizeof (u_char));
  hmac_new = (u_char *) malloc (sha1_hashsize * sizeof (u_char));
/*  iv_buf = (char *) malloc (block_length * sizeof (char)); */

  cur_bytes_read = read (fin, block_buf, block_length);
  if (cur_bytes_read <= 0 || cur_bytes_read < block_length) {
    perror (getprogname ());
    bzero (raw_sk, raw_len);
    bzero (sk_aes, block_length);
    bzero (sk_sha, block_length);
    free (raw_sk);
    free (sk_aes);
    free (sk_sha);
    free (block_buf);
    free (iv);
    exit (-1);
  }

  bcopy (block_buf, iv, block_length); /* get original IV directly, casuse IV not AESed */

  /* compute the HMAC-SHA1 as you go */
  hmac_sha1_update (sk_sha, iv, block_length);

  /* Create plaintext file---may be confidential info, so permission is 0600 */
  if ((fdptxt = open (ptxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());
    bzero (raw_sk, raw_len);
    bzero (sk_aes, block_length);
    bzero (sk_sha, block_length);
    free (raw_sk);
    free (sk_aes);
    free (sk_sha);
    free (block_buf);
    free (iv);
    exit (-1);
  }

  /* CBC (Cipher-Block Chaining)---Decryption
   * decrypt the current block and xor it with the previous one 
   */
        while ( (cur_bytes_read = read (fin, block_buf, block_length + sha1_hashsize + 2 )) > 0 ) 
        {
  aes_decrypt (sk_aes, dcrypt_buf, block_buf);
  hmac_sha1_update (sk_sha, block_buf, block_length);

/* XOR the DECRYPT buffer with IV to get PLAIN TEXT */
  for (i = 0; i < block_length; i++) {
    *(dcrypt_buf + i) = *(iv + i) ^ *(dcrypt_buf + i);
  }

  /* Recall that we are reading sha_hashsize + 2 bytes ahead: now that 
   * we just consumed aes_blocklen bytes from the front of the buffer, we
   * shift the unused sha_hashsize + 2 bytes left by aes_blocklen bytes 
   */  
  if (cur_bytes_read < block_length + sha1_hashsize + 2) {
    padlen = (int) *(block_buf + cur_bytes_read - 1);

    bcopy ( ((void *)block_buf) + block_length, hmac_old, sha1_hashsize);
  }
  else {
/*  off_t lseek(int fd, off_t offset, int whence); */
    lshift_len = lseek (fin, -(sha1_hashsize + 2), SEEK_CUR); /* backward <-- negative */
    if (lshift_len < sha1_hashsize + 2) {
      printf("Error: left shift length < %d + 2\n", sha1_hashsize);
      perror (getprogname ());
      close (fdptxt);
      bzero (raw_sk, raw_len);
      bzero (sk_aes, block_length);
      bzero (sk_sha, block_length);
      free (raw_sk);
      free (sk_aes);
      free (sk_sha);
      free (block_buf);
      free (iv);
      exit (-1);
    }

    /* write the decrypted chunk to the plaintext file */
    status = write (fdptxt, dcrypt_buf, block_length);
    if (status == -1) {
      perror (getprogname ());
      close (fdptxt);
      bzero (raw_sk, raw_len);
      bzero (sk_aes, block_length);
      bzero (sk_sha, block_length);
      free (raw_sk);
      free (sk_aes);
      free (sk_sha);
      free (block_buf);
      free (iv);
      exit (-1);
    }
  
    /* reset IV = newly read block_buf */
    bcopy (block_buf, iv, block_length);
  
  }
        }

  /* now we can finish computing the HMAC-SHA1 */
/*  hmac_sha1_update (sk_sha, block_buf, block_length); */
  hmac_sha1_final ((char *) raw_sk + block_length, block_length, sk_sha, hmac_new);
  
  /* compare the HMAC-SHA1 we computed with the value read from fin */
  /* NB: if the HMAC-SHA1 mac stored in the ciphertext file does not match 
   * what we just computed, destroy the whole plaintext file! That means
   * that somebody tampered with the ciphertext file, and you should not
   * decrypt it.  Otherwise, the CCA-security is gone.
   */
  hash_eql = bcmp ((void *) hmac_old, (void *) hmac_new, sha1_hashsize);
  if (hash_eql != 0) {
    printf ("Error: HMAC-SHA1 does NOT equal.\n");
    perror (getprogname ());
    bzero (raw_sk, raw_len);
    bzero (sk_aes, block_length);
    bzero (sk_sha, block_length);
    free (raw_sk);
    free (sk_aes);
    free (sk_sha);
    free (block_buf);
    free (iv);
    close(fdptxt);
    unlink(ptxt_fname);	
    exit (-1);
  }

  /* write the last chunk of plaintext---remember to chop off the trailing
   * zeroes, (how many zeroes were added is specified by the last byte in 
   * the ciphertext (padlen).
   */
  aes_decrypt (sk_aes, dcrypt_buf, block_buf);

/* XOR the DECRYPT buffer with IV to get PLAIN TEXT */
  for (i = 0; i < block_length; i++) {
    *(dcrypt_buf + i) = *(iv + i) ^ *(dcrypt_buf + i);
  }

  status = write (fdptxt, dcrypt_buf, block_length - padlen);
  if (status == -1) {
    perror (getprogname ());
    close (fdptxt);
    bzero (raw_sk, raw_len);
    bzero (sk_aes, block_length);
    bzero (sk_sha, block_length);
    free (raw_sk);
    free (sk_aes);
    free (sk_sha);
    free (block_buf);
    free (iv);
    exit (-1);
  }

  aes_clrkey (sk_aes);
  free (sk_aes);  

  close (fdptxt);
}

void 
usage (const char *pname)
{
  printf ("Simple File Decryption Utility\n");
  printf ("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
  printf ("       if a symmetric key sk cannot be found in SK-FILE.\n");
  printf ("       Otherwise, tries to use sk to decrypt the content of\n");
  printf ("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf ("       in PTEXT-FILE; if a decryption problem is encountered\n"); 
  printf ("       after the processing started, PTEXT-FILE is truncated\n");
  printf ("       to zero-length and its previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdctxt;
  char *sk = NULL;
  size_t sk_len = 0;

  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdctxt = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);
      
      exit (-1);
    }
  }   
  else {
    setprogname (argv[0]);

    /* Import symmetric key from argv[1] */
    if (!(sk = import_sk_from_file (&sk, &sk_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    decrypt_file (argv[3], sk, sk_len, fdctxt);    

    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
    bzero (sk, sk_len);
    free (sk);

    close (fdctxt);
  }

  return 0;
}
