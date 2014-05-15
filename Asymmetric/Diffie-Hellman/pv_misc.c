#include "pv.h"

#ifndef HAVE_GETPROGNAME
char *my_progname = NULL; 

const char *
getprogname(void) 
{
  return (my_progname ? my_progname : "");
}

void 
setprogname(const char *n) 
{
  int i, j;

  /* truncate n if longer than MY_MAXNAME chars */
  for (i = 0; (i < MY_MAXNAME) && n[i]; i++)
    ; /*intentionally empty */

  /* copy into my_progname as long as there is space ... */
  for (j = 0; (j < i) && (my_progname + j); j++)
    my_progname[j] = n [j];

  /* need more space? */
  if ((j < i) || !(my_progname [j])) {
    my_progname = (char *) realloc (my_progname, (i + 1)* sizeof (char));
    /* complete the copying */
    for (; j < i; j++) {
      assert (my_progname + j);
      my_progname[j] = n[j];
    }
  }

  assert (my_progname + j);
  my_progname[j] = '\0';
}  
#endif /* HAVE_GETPROGNAME */


void
ri (void)
{
  char *random_devs[] = {"/dev/urandom",
			 "/dev/random",
			 0};
  int i;
  int fd;
  int done = 0;

  /* first, check if one of /dev/random, /dev/urandom or /dev/prandom */   
  for (i = 0; (!done) && random_devs[i]; i++) {
    if ((fd = open (random_devs[i], O_RDONLY, 0600)) == -1) { 
      if (errno == ENOENT) {
	continue;      
      }
      else {
	printf ("%s: trouble reading from %s\n", 
		getprogname (), random_devs[i]);
	perror (getprogname ());
	
	exit (-1);
      }
    }
    else {
      /* we found a random device; let's get some bytes from it */
      ssize_t seed_len = 32;
      char *seed = (char *) malloc (seed_len * sizeof (char));
      int cur_bytes_read, bytes_read = 0; 

      bytes_read = 0;
      do {
	cur_bytes_read = read (fd, seed, seed_len - bytes_read);
	bytes_read += cur_bytes_read;
      } while ((bytes_read < seed_len) && (cur_bytes_read > 0));
      if (bytes_read == seed_len) {
	prng_seed (seed, seed_len);
	done = 1;
      }
      else {
	printf ("%s: trouble reading from %s\n", 
		getprogname (), random_devs[i]);
	perror (getprogname ());
	
	exit (-1);	
      }
      
      bzero (seed, seed_len);
      free (seed);
      seed = NULL;
    }
  }

  if (!done) {
    /* no /dev/?random device */
    /* quick'n dirty way to inialize the pseudorandom number generator */
    struct {
      int pid;
      int time;
    } rid;
    
    rid.pid = getpid ();
    rid.time = time (NULL);
    prng_seed (&rid, sizeof (rid));
    bzero (&rid, sizeof (rid));
  }
}

char *
import_from_file (int fd)
{
  /* XXX - reads the entire file into memory as a null-terminated string */
  /* XXX - big files could run it out of memory */
  size_t bufsize = 512; /* initial bufsize is enough for 1024-bit keys */
  size_t tot;           /* total bytes read so far */
  ssize_t cur;           /* no bytes read in the last read */
  char *buf = (char *) malloc (bufsize * sizeof (char));
  
  tot = 0;
  do {
    cur = read (fd, buf + tot, bufsize - tot); 
    tot += cur;
    if (bufsize == tot) {/* saturated current size; double the buffer */
      bufsize <<= 1;
      buf = (char *) realloc (buf, bufsize);
    }
  } while (cur > 0);
  if (cur == -1) {
    printf ("%s: trouble importing key from file\n", 
	    getprogname ());
    perror (getprogname ());
    
    free (buf);
    close (fd);
    
    exit (-1); 
  } 
  else {
    assert (cur == 0);
    buf [tot] = '\0'; /* when we exit the reading loop, tot < bufsize */
  }

  return buf;
}

char *
import_sk_from_file (char **raw_sk_p, size_t *raw_len_p, int fdsk)
{
  char *armored_key = import_from_file (fdsk);
  ssize_t dearmored_len = dearmor64len (armored_key);

  if ((-1 == dearmored_len)) {
    /* error when dearmoring */
    
    *raw_sk_p = NULL;
    *raw_len_p = 0;
  }
  else {
    *raw_len_p = (size_t) dearmored_len;
    *raw_sk_p = (char *) malloc (dearmored_len * sizeof (char));
    dearmor64 (*raw_sk_p, armored_key);
  }    

  return (*raw_sk_p);
}

int 
write_chunk (int fd, const char *buf, u_int len) 
{
  int cur_bytes_written;
  u_int bytes_written = 0;

  while (bytes_written < len) {
    if ((cur_bytes_written = write (fd, buf + bytes_written,
					len - bytes_written)) != -1) {
	  bytes_written += cur_bytes_written;
    }
    else {
      return -1;
    }
  }

  return 0;
}
