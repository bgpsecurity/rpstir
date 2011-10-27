package threshsig;

import java.math.BigInteger;

/**
 * A Key Dealer for an RSA based (k,l) Threshold Signature Scheme<BR>
 * 
 * Reference: "Practical Threshold Signatures",<br>
 * Victor Shoup (sho@zurich.ibm.com), IBM Research Paper RZ3121, 4/30/99<BR>
 * 
 * @author Steve Weis <sweis@mit.edu>
 */
public class Dealer {

  // Constants and variables
  // ............................................................................
  private int keysize;

  private KeyShare[] shares = null;

  /** Group Verifier */
  private BigInteger vk = null;

  /** Group Key */
  private GroupKey gk;

  /** Indicates whether this dealer has initialized a set of keys */
  private boolean keyInit;

  /** Randomly generated polynomial used to generate shares */
  private Poly poly;

  // Constructors
  // ............................................................................

  /**
   * Create a new instance of a key dealer
   * 
   * @param provider -
   *          the provider to use for RSA KeyPair generator
   * @param keysize -
   *          the size of the group key
   */
  public Dealer(final int keysize) {
    if (DEBUG)
      debug("Testing " + keysize + " bit Keys...");
    this.keysize = keysize;
    this.keyInit = false;
  }

  // Public Methods
  // ............................................................................

  /**
   * Generate a group public key and l shares for a (k,l) <BR>
   * threshold signatures scheme<BR>
   * 
   * @param k -
   *          k valid signatures will verify
   * @param l -
   *          l members of the group will receive shares
   * 
   * @throws ThresholdSigException
   */
  public void generateKeys(final int k, final int l) {

    BigInteger pr, qr, p, q, d, e, m, n;
    BigInteger groupSize;
    n = m = pr = qr = null;

    // Create the group key pair
    if (DEBUG)
      debug("Attempting to generate group keypair..");

    /* Generate a Sophie Germain prime keypair */
    // pr = generateSophieGermainPrime();
    // qr = generateSophieGermainPrime();
    p = SafePrimeGen.generateStrongPrime(keysize, ThreshUtil.getRandom());
    q = SafePrimeGen.generateStrongPrime(keysize, ThreshUtil.getRandom());

    pr = (p.subtract(ThreshUtil.ONE)).divide(ThreshUtil.TWO);
    qr = (q.subtract(ThreshUtil.ONE)).divide(ThreshUtil.TWO);

    // m = pr*qr
    m = pr.multiply(qr);

    // p = 2*pr + 1
    // p = (pr.multiply(TWO)).add(ONE);

    // q = 2*qr + 1
    // q = (qr.multiply(TWO)).add(ONE);

    // n = p*q
    n = p.multiply(q);

    // the RSA public exponent must be a prime bigger than
    // l, the size of the group
    groupSize = BigInteger.valueOf(l);

    // If group size is less than Fermat's prime, just use it.
    if (groupSize.compareTo(ThreshUtil.F4) < 0)
      e = ThreshUtil.F4;
    // Otherwise pick a prime bigger then groupSize
    else
      e = new BigInteger(groupSize.bitLength() + 1, 80, ThreshUtil.getRandom());

    // Note: This is not a standard RSA Key Pair
    // Usually:
    // BigInteger phi = (p.subtract(ONE)).multiply(q.subtract(ONE));
    // d = e.modInverse(phi);
    d = e.modInverse(m);

    // Create Secret KeyShares and KeyShare Verifiers
    // Note: We don't use the private exponent 'd' after this
    shares = this.generateKeyShares(d, m, k, l, n);

    // Create verification shares
    vk = this.generateVerifiers(n, shares);

    // Create a group key
    this.gk = new GroupKey(k, l, keysize, vk, e, n);
    this.keyInit = true;
  }

  /**
   * Returns the group key
   */
  public GroupKey getGroupKey() throws ThresholdSigException {
    checkKeyInit();
    return this.gk;
  }

  /**
   * Returns the initialized secret key shares
   */
  public KeyShare[] getShares() throws ThresholdSigException {
    checkKeyInit();
    return shares;
  }

  // Initialization Checks
  // ............................................................................

  private void checkKeyInit() throws ThresholdSigException {
    if (keyInit == false) {
      if (DEBUG)
        debug("Key pair has not been initialized by generateKeys()");
      throw new ThresholdSigException(
          "Key pair has not been initialized by generateKeys()");
    }
  }

  // Private Methods
  // ............................................................................
  /**
   * 
   * Generates secret shares for a (k,l) threshold signatures scheme<BR>
   * 
   * @param k -
   *          k valid signatures will verify
   * @param l -
   *          l members of the group will receive shares
   * 
   * @return An array of l secret shares
   * @throws ThresholdSigException
   */
  // TODO: Merge Dealer.generateShares and Dealer.generateVerifiers
  // and generate them simultaneously
  private KeyShare[] generateKeyShares(final BigInteger d, final BigInteger m,
      final int k, final int l, final BigInteger n) {
    BigInteger[] secrets;
    BigInteger rand;
    int randbits;

    this.poly = new Poly(d, k - 1, m);
    secrets = new BigInteger[l];
    randbits = n.bitLength() + ThreshUtil.L1 - m.bitLength();

    // Generates the valies f(i) for 1<=i<=l
    // and add some large multiple of m to each value
    for (int i = 0; i < l; i++) {
      secrets[i] = poly.eval(i + 1);
      rand = (new BigInteger(randbits, ThreshUtil.getRandom())).multiply(m);
      secrets[i] = secrets[i].add(rand);
    }

    final BigInteger delta = Dealer.factorial(l);

    final KeyShare[] s = new KeyShare[l];
    for (int i = 0; i < l; i++)
      s[i] = new KeyShare(i + 1, secrets[i], n, delta);

    return s;
  }

  /**
   * Creates verifiers for secret shares to prevent corrupting shares<BR>
   * 
   * Computes v[i] = v^^s[i] mod n, where v is an element of QR_n <BR>
   * Returns the group verifier and sets the verifier in each share<br>
   * 
   * @param n -
   *          Size of modulo for group key
   * @param secrets -
   *          array of shares
   * 
   * @return the group verifier
   */
  // TODO: Merge Dealer.generateShares and Dealer.generateVerifiers
  // and generate them simultaneously
  private BigInteger generateVerifiers(final BigInteger n,
      final KeyShare[] secrets) {

    debug("Generating Verifiers");

    // BigInteger[] v;
    BigInteger rand = null;

    // v = new BigInteger[secrets.length];

    for (final KeyShare element : secrets) {
      // rand is an element of Q*n (squares of relative primes mod n)
      while (true) {
        rand = new BigInteger(n.bitLength(), ThreshUtil.getRandom());
        // ensure that rand is relatively prime to n
        final BigInteger d = rand.gcd(n);
        if (d.compareTo(ThreshUtil.ONE) == 0)
          break;
        // Else d was not relatively prime
        // Note: This should be very rare
        debug("Verifier was not relatively prime");
      }
      // Rand is an element of QsubN - square mod n
      // This value is the group verifier
      rand = rand.multiply(rand).mod(n);

      element.setVerifiers(rand.modPow(element.getSecret(), n), rand);
    }

    return rand;
  }

  /**
   * Returns the factorial of the given integer as a BigInteger
   * 
   * @return l!
   */
  private static BigInteger factorial(final int l) {
    BigInteger x = BigInteger.valueOf(1l);
    for (int i = 1; i <= l; i++)
      x = x.multiply(BigInteger.valueOf(i));

    return x;
  }

  // Debugging
  // ............................................................................

  private final static boolean DEBUG = true;

  private static void debug(final String s) {
    System.err.println("Dealer: " + s);
  }

  public static void main(final String[] args) {
    int keysize = 512;
    if (args.length > 0)
      try {
        keysize = Integer.parseInt(args[0]);
      } catch (final Exception e) {
      }

    final Dealer d = new Dealer(keysize);
    d.generateKeys(3, 5);

  }

  // Self-Testing and Verification Methods
  // ............................................................................

  // debug
  private void verifyPoly() {
    final Poly f = new Poly(ThreshUtil.ONE, 4, ThreshUtil.FOUR);
    debug(f.toString());
    debug(f.eval(0).toString(10));
    debug(f.eval(1).toString(10));
    debug(f.eval(2).toString(10));
  }

  // debug
  private void verifyKeyShares(final Poly f, final BigInteger secrets[],
      final BigInteger m) {
    for (final BigInteger element : secrets) {
      debug("Secret: " + element.toString(16));
      debug("f(i) mod m: " + element.mod(m).toString(16));
      debug("Secret mod m: " + element.mod(m).toString(16));
    }
  }
}
