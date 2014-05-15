#include "skgu.h"

void 
usage (const char *pname)
{
  printf ("Simple Certificate Generation Utility\n");
  printf ("Usages: 1) %s init\n", pname);
  printf ("           Initializes the certification mechanism.\n\n");
  printf ("           A new signing/verification keypair is generated and\n");
  printf ("           stored in files ($PWD)/.pki/ca.{sk,vk}\n");
  printf ("           (The directory ($PWD)/.pki/ is created if it didn't exist.)\n\n");
  printf ("        2) %s cert [-g PRIV-FILE] [-o CERT-FILE] [-e DAYS] PUB-FILE ID\n", pname);
  printf ("           Creates a certificate under the CA located at ($PWD)/.pki.\n\n");
  printf ("           Exits if ($PWD)/.pki/ or ($PWD)/.pki/ca.sk do not exist\n");
  printf ("           Otherwise, signs a certificate binding ID to the public key\n");
  printf ("           contained in PUB-FILE.\n");
  printf ("           (Notice that ID cannot contain the ',' (comma) character.)\n");
  printf ("           If the option -g (generate) is specified, a new key pair\n");
  printf ("           for ID is generated, and stored in PRIV-FILE and PUB-FILE.\n");
  printf ("           By default, the certificate is valid for 30 days, and it is\n");
  printf ("           stored in a file named ID.cert, unless the -o option is used.\n");
  printf ("           (In both cases, previous content is lost if output file existed.)\n");
  printf ("           The -e option can be used to set the duration (in days) of the\n");
  printf ("           validity period.  A value of 0 means \"never expires\";\n"); 
  printf ("           otherwise, the maximum duration is 4 years = 1461 days.\n"); 
  printf ("           (Greater values result in no certificate being created.)\n\n");  
  printf ("        3) %s check CERT-FILE PUB-FILE ID\n", pname);
  printf ("           Checks that the certificate stored in CERT-FILE was properly\n");
  printf ("           signed by the CA located at ($PWD)/.pki, that it has not expired,\n");
  printf ("           and that it corresponds to the identity ID and to the public key\n");
  printf ("           stored in PUB-FILE.\n");
  printf ("           The result of the above checks is then printed to standard output.\n");
  exit (-1);
}

dckey *
g_option (const char *priv_file)
{
  char *raw_pub = NULL;
  dckey *pub = NULL;
  dckey *priv = dckeygen (DC_ELGAMAL, 1024, NULL); 
  write_privfile (priv_file, priv);
  
  if (!(raw_pub = dcexport_pub (priv)) 
      || ! (pub = dcimport_pub (raw_pub))) {
    printf ("%s: trouble exporting public key\n", getprogname ());
    check_n_free (&raw_pub);
    dcfree (priv);

    exit (-1);
  }

  check_n_free (&raw_pub);
  return pub;
}

char *
o_option (const char *c_file)
{
  return xstrdup (c_file);
}

int
e_option (const char *days)
{
  int nchars = strlen (days);
  if (nchars > 4)    nchars = 4;

  int d = days ? asc_to_num (days, nchars) : -1;
  
  return ((d >= 0) && (d <= 1461)) ? d : -1;
}

/* Creates the directory and files for the certificate mechanism */
void 
pki_init(void)
{
  int status;
  int fdca;
  dckey *ca = NULL;

  if ((((status = mkdir ("./.pki", 0700)) != -1) || (errno == EEXIST))
      && ((fdca = open ("./.pki/ca.sk",
			O_WRONLY|O_TRUNC|O_CREAT, 0600)) != -1)) {
    close (fdca);
    fdca = -1;
    /* key_type and nbits should be command-line options, but are
       just hard-coded for now */
    ca = dckeygen (DC_RABIN, 1024, NULL);
    /* now ca contains the newly created ca private key */
    write_privfile ("./.pki/ca.sk", ca);
    write_pubfile ("./.pki/ca.vk", ca);
  }
  else if (errno == EACCES) {
    perror (getprogname ());
    
    exit (-1);
  }
  else 
    usage (getprogname ());
}

void
parse_options (dckey **ppub, char **pcfile, int *pdur, int argc, char **argv)
{
  char opt;
  char *opt_arg;
  int arg_idx = 2; 

  *ppub = NULL;
  *pcfile = NULL;
  *pdur = -1;

  while ((arg_idx < argc) && (argv[arg_idx][0] == '-')) {
    /* bail out upon seeing a '-' without any switch */
    if (!(opt = argv[arg_idx][1]))    usage (argv[0]);
    /* locate the argument to this option */
    opt_arg = (argv[arg_idx][2] != '\0')
      ? &(argv[arg_idx][2])
      : argv[++arg_idx];
    /* bail out if there is no argument after the switch */
    if (arg_idx == argc)    usage (argv[0]);
    ++arg_idx;
    switch (opt) {
    case 'g':
      /* seen a -g option already? */
      if (*ppub) {
	  dcfree (*ppub);
	  usage (argv[0]);
	}
	else 
	  *ppub = g_option (opt_arg);
	break;
      case 'o':
	/* seen a -o option already? */
	if (*pcfile) {
	  if (*ppub) dcfree (*ppub);
	  usage (argv[0]);
	}
	else 
	  *pcfile = o_option (opt_arg);
	break;
      case 'e':
	/* seen a -e option already? */
	if (*pdur != -1) {
	  if (*ppub) dcfree (*ppub);
	  usage (argv[0]);
	}
	else
	  /* a -1 return value means "out of range"; display usage notice */
	  if ((*pdur = e_option (opt_arg)) == -1) usage (argv[0]);	  
	break;
      default:
	usage (argv[0]);
      }
    }      
    /* now we should have exactly two more args */ 
    if (arg_idx != argc - 2) 
      usage (argv[0]);
}

int 
main (int argc, char **argv)
{
  int fdca, fdpub;
  dckey *ca = NULL, *pub = NULL;
  char *id = NULL;
  char *cert_file = NULL, *pub_file = NULL;
  int duration = -1;

  ri ();

  if (argc < 2) 
    usage (argv[0]);
  else if (argc == 2) {
    if (strcmp (argv[1], "init") != 0)
      usage (argv[0]);
    else {
      setprogname (argv[0]);
      pki_init ();      
    }
  }
  else if (argc == 5) {
    if (strcmp (argv[1], "check") != 0)
      usage (argv[0]);
    else {
      setprogname (argv[0]);
      cert_clr (pki_check (argv[2], argv[3], argv[4]));

      exit (0);
    }
  }
  else if (strcmp (argv[1], "cert") != 0) {
    usage (argv[0]);
  }
  else {
    /* cert commnad */
    setprogname (argv[0]);

    /* first, let's take care of the options, if any */
    parse_options (&pub, &cert_file, &duration, argc, argv);

    /* the last two args are PUB-FILE and ID */
    pub_file = argv[argc - 2];
    id = argv[argc - 1];
    /* set up default values for parameters not affected by the options */
    if (!cert_file) {
      /* default cert_file is ID.cert */
      if (cat_str (&cert_file, id)
	  || cat_str (&cert_file, ".cert")) {
	free (cert_file);
	exit (-1);	    
      }
    }
      
    if (duration == -1) 
      /* default duration is 30 days */
      duration = 30;

    /* take care of the public key that we are certifying */
    /* if the -g option was used, we have to write pub to pub_file */
    if (pub) 
      write_pubfile (pub_file, pub); 
    /* otherwise, import pub from pub_file */
    else {
      if ((fdpub = open (pub_file, O_RDONLY)) == -1) {
	if (errno == ENOENT) {
	  usage (argv[0]);
	}
	else {
	  perror (argv[0]);
	  
	  exit (-1);
	}
      }
      else if (!(pub = import_pub_from_file (fdpub))) {
	printf ("%s: no public key found in %s\n", argv[0], pub_file);
      
	close (fdpub);
	exit (-1);
      }
      close (fdpub);
      fdpub = -1;
    }
    /* now read the ca private key from ./.pki/ca.sk */
    if ((fdca = open ("./.pki/ca.sk", O_RDONLY)) == -1) {
      if (errno == ENOENT) {
	usage (argv[0]);
      }
      else {
	perror (argv[0]);
	
	exit (-1);
      }
    }   
    else {
      if (!(ca = import_priv_from_file (fdca))) {
	printf ("%s: no private key found in %s\n", 
		argv[0], "./.pki/ca.sk");
	
	close (fdca);
	exit (-1);
      }
      close (fdca);
      fdca = -1;

      /* prepare a cert, sign it and write it to cert_file */
      switch (cert_sign_n_write (ca, id, pub, duration, cert_file)) {
      case 0:
	/* no error */
	/* the ca signing key is not needed anymore: wipe it out */
	dcfree (ca);
	ca = NULL;
	break;
      case -1:
	/* trouble with the write system call */
	check_n_free (&cert_file);
	dcfree (ca);
	exit (-1);
      case -2:
	/* trouble preparing/signinig the certificate */
	check_n_free (&cert_file);
	dcfree (ca);
	exit (-1);
      default:
	check_n_free (&cert_file);
	dcfree (ca);
	exit (-1);
      }

      assert (cert_verify (cert_read (cert_file)));
      
      dcfree (pub);
      pub = NULL;
    }
  }
  check_n_free (&cert_file);
  
  return 0;
}
