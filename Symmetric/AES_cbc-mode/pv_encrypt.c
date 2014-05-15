#include "pv.h"

void
encrypt_file (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /*************************************************************************** 
   * Task: Read the content from file descriptor fin, encrypt it using raw_sk,
   *       and place the resulting ciphertext in a file named ctxt_fname.
   *       The encryption should be CCA-secure, which is the level of 
   *       cryptographic protection that you should always expect of any 
   *       implementation of an encryption algorithm.
   * 
   * Here are some guidelines, but you are welcome to make variations, as long
   * as you can argue that your code still attains CCA security.
   *
   * One approach is to use AES in CBC-mode, and then append an HSHA-1  
   * mac of the resulting ciphertext. (Always mac after encrypting!)  
   * The libdcrypt library also contains implementations of AES 
   * (~class/src/dcrypt/aes.c) and of HSHA-1 (~class/src/dcrypt/sha1.c).  
   * However, you should take care of using AES in CBC-mode, as the
   * library only gives access to the basic AES block cipher functionality.
   * (You can use another mode of operation instead of CBC-mode.)
   *
   * Notice that the key used to compute the HSHA-1 mac must be different 
   * from the one used by AES. (Never use the same cryptographic key for 
   * two different purposes: bad interference could occur.) 
   *
   * Recall that AES can only encrypt blocks of 128 bits, so you should use
   * some padding in the case that the length (in bytes) of the plaintext 
   * is not a multiple of 16.  This should be done in a way that allow proper 
   * decoding after decryption: in particualr,  the recipient must have a way 
   * to know where the padding begins so that it can be chopped off. 
   * One possible design is to add enough 0 bytes to the plaintext so as to
   * make its length a multiple of 16, and then append a byte at the end
   * specifying how many zero-bytes were appended.
   *
   * Thus, the overall layout of an encrypted file will be:
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
   ***************************************************************************/

  int fdctxt; /* file descriptor ciphertext file */
  int status, padlen;
  size_t i, cur_bytes_read;
  char *iv; /* hold the IV */
  aes_ctx *sk_aes;
  sha1_ctx *sk_sha;
  size_t block_length = CCA_STRENGTH;
/*  u_int i, j; */
  char *block_buf;
  u_char *hmac_buf;

  /* Create the ciphertext file---the content will be encrypted, 
   * so it can be world-readable! */
  if ((fdctxt = open (ctxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());
    bzero (raw_sk, raw_len);
    free (raw_sk);
    exit (-1);
  }

  /* initialize the pseudorandom generator (for the IV) */
  iv = (char *) malloc (block_length * sizeof (char));
  ri ();
  prng_getbytes (iv, block_length);

  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the CBC-AES encryption ...*/
  sk_aes = (aes_ctx *) malloc (sizeof (aes_ctx));
  aes_setkey (sk_aes, (void *) raw_sk, block_length);

  /* ... and the second part for the HMAC-SHA1 */
  sk_sha = (sha1_ctx *) malloc (sizeof (sha1_ctx));
  hmac_sha1_init ( ((char *) raw_sk) + block_length, block_length, sk_sha);

  /* Compute the HSHA-1 mac while you go */
  hmac_sha1_update (sk_sha, iv, block_length);


  /* Now start processing the actual file content using symmetric encryption */
  /* Remember that CBC-mode needs a random IV (Initialization Vector) */
/* DONE initialization before, now wirte IV to the begining of ctxt_file */
  status = write (fdctxt, iv, block_length);
  if (status == -1) {
    perror (getprogname ());
    close (fdctxt);
    bzero (raw_sk, raw_len);
    bzero (sk_aes, block_length);
    bzero (sk_sha, block_length);
    bzero (iv, block_length);
    free (raw_sk);
    free (sk_aes);
    free (sk_sha);
    free (iv);
    exit(-1);
  }

  /* CBC (Cipher-Block Chaining)---Encryption
   * xor the previous ciphertext's block with the next plaintext's block;
   * then encrypt it with AES and write the resulting block */
  block_buf = (char *) malloc (block_length * sizeof (char));

  while ( (cur_bytes_read = read (fin, block_buf, block_length)) > 0 ) {

    /* xor the previous ciphertext's block with the next plaintext's block */
    for (i = 0; i < block_length; i++) {
      *(block_buf + i) = *(iv + i) ^ *(block_buf + i);
    }

    /* void aes_encrypt (const aes_ctx *aes, void *buf, const void *ibuf); */
    aes_encrypt (sk_aes, iv, block_buf);
    /* void hmac_sha1_update (sha1_ctx *sc, const void *data, size_t len); */
    hmac_sha1_update (sk_sha, iv, block_length);

  /* Don't forget to pad the last block with trailing zeroes */
    if (cur_bytes_read < block_length) {
      padlen = block_length - cur_bytes_read;
    }

  /* write the last chunk */
/* iv is the encrypted last chunk */
    status = write (fdctxt, iv, block_length);
    if (status == -1) {
      perror (getprogname ());
      close (fdctxt);
      bzero (raw_sk, raw_len);
      bzero (sk_aes, block_length);
      bzero (sk_sha, block_length);
      bzero (iv, block_length);
      free (raw_sk);
      free (sk_aes);
      free (sk_sha);
      free (iv);
      bzero (block_buf, block_length);
      free (block_buf);
      exit (-1);
    }

/* ase block_buf as all 0's, so no need to padding 0's anymore */
    bzero (block_buf, block_length);
  }
  
  
  /* Finish up computing the HSHA-1 mac and write the 20-byte mac after
   * the last chunk of the CBC ciphertext */
  hmac_buf = (u_char *) malloc (sha1_hashsize * sizeof (u_char));
  hmac_sha1_final ( ((char *)raw_sk) + block_length, block_length, sk_sha, hmac_buf);

  status = write (fdctxt, hmac_buf, sha1_hashsize);

  /* Remember to write a byte at the end specifying how many trailing zeroes
   * (possibly none) were added */
  status = write (fdctxt, &padlen, 1);
  if (status == -1) {
    perror (getprogname ());
    close (fdctxt);

    bzero (raw_sk, raw_len);
    bzero (sk_aes, block_length);
    bzero (sk_sha, block_length);
    bzero (iv, block_length);
    free (raw_sk);
    free (sk_aes);
    free (sk_sha);
    free (iv);

    bzero (block_buf, block_length);
    bzero (hmac_buf, sha1_hashsize);
    free (block_buf);
    free (hmac_buf);
    exit(-1);
  }

  close (fdctxt);

  aes_clrkey (sk_aes);

  bzero (sk_aes, block_length);
  bzero (sk_sha, block_length);
  bzero (iv, block_length);
  free (sk_aes);
  free (sk_sha);
  free (iv);

  bzero (block_buf, block_length);
  bzero (hmac_buf, sha1_hashsize);
  free (block_buf);
  free (hmac_buf);
}

void 
usage (const char *pname)
{
  printf ("Personal Vault: Encryption \n");
  printf ("Usage: %s SK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or PTEXT-FILE don't exist.\n");
  printf ("       Otherwise, encrpyts the content of PTEXT-FILE under\n");
  printf ("       sk, and place the resulting ciphertext in CTEXT-FILE.\n");
  printf ("       If CTEXT-FILE existed, any previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdptxt;
  char *raw_sk;
  size_t raw_len;

  /* YOUR CODE HERE */

  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdptxt = open (argv[2], O_RDONLY)) == -1)) {
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
    if ( !(import_sk_from_file (&raw_sk, &raw_len, fdsk)) ) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    encrypt_file (argv[3], raw_sk, raw_len, fdptxt);    

    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
    bzero (raw_sk, raw_len);
    free (raw_sk);

    close (fdptxt);
  }

  return 0;
}
