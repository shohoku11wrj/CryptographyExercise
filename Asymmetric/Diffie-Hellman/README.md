Ref: http://www.cs.stevens.edu/~nicolosi/classes/14sp-cs579/lab2/lab2.html

This is one of my assignment for course CS579 Foundations of Cryptography at Stevens.

Also see: http://rangerway.com/way/2014/05/07/public-key-one-elgamal/

<backquote>
A simple utility that uses public-key cryptography to securely generate shared secret keys between two parties
</backquote>

## Requirement

see: http://www.cs.stevens.edu/~nicolosi/classes/14sp-cs579/lab0/install-libs.html

__GNU MP__
GNU Multiple Precision arithmetic library
The gmp library provides support for big integers and many number-theoretics functions, which are needed for the implementation of most cryptographic primitives. 

__Libdcrypt__
Download dcrypt from [libdcrypt-0.6.tar.gz](http://www.cs.stevens.edu/~nicolosi/classes/14sp-cs579/lab0/libdcrypt-0.6.tar.gz).

## Implementation

In a non-interactive Diffie-Hellman key exchange, each party is
assumed to have preliminary obtained (<em>e.g.,</em>, via email) the
public key for the other party, certified under the signing key of a
mutually trusted certification authority.  After having verified the
certificate and the public key for the other party, you will derive
the shared key <code>K<sub>s</sub></code> according to the following
equation:

<p class="centered">
<table>
<tr><td>
<code>K<sub>m</sub> = SHA1 (DH(Alice.pub,Bob.pub), first_id
    || second_id)</code> <br>
</td></tr>    
<tr><td>
<code>K<sub>s0</sub> = HMAC-SHA1 (K<sub>m</sub>, label
    || "AES-CBC")</code>
</td></tr>
<tr><td>
<code>K<sub>s1</sub> = HMAC-SHA1 (K<sub>m</sub>, label
    || "HMAC-SHA1")</code>
</td></tr>
<tr><td>
<code>K<sub>s</sub> = </code> &lt; <i>concatenation of first 16 bytes
of</i> <code>K<sub>s0</sub></code> <i>with first 16 bytes
of</i> <code>K<sub>s1</sub></code> &gt;
</td></tr>
</table>
<p>

Above, <code>||</code> denotes concatenation (juxtaposition) of bit strings.
<code>DH(.,.)</code> represents the Diffie-Hellman function:
<code>DH(g<sup>a</sup> mod p, g<sup>b</sup> mod p) = 
g<sup>ab</sup> mod p</code>.  <code>first_id</code> and
<code>second_id</code> correspond's to the id used for the two parties
in the command line of <code>skgu_nidh</code> (in lexicographical order, to ensure that both parties will be computing the same value).

## Usage

### Initialization

$ ./skgu_pki init 

### Generate Key Pair

$ ./skgu_pki cert -g alice.priv alice.pub alice

$ ./skgu_pki cert -g bob.priv bob.pub bob 

### Exchange Key

$ ./skgu_nidh alice.priv alice.cert alice bob.pub bob.cert bob example1

$ ./skgu_nidh bob.priv bob.cert bob alice.pub alice.cert alice example1 

$ diff example1-alice.b64 example1-bob.b64

