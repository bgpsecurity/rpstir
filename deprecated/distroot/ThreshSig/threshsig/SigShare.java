package threshsig;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * Signature Shares Class<BR>
 * Associates a signature share with an id & wraps a static verifier
 * 
 * Reference: "Practical Threshold Signatures",<br>
 * Victor Shoup (sho@zurich.ibm.com), IBM Research Paper RZ3121, 4/30/99<BR>
 * 
 * @author Steve Weis <sweis@mit.edu>
 */
public class SigShare {

  // Constants and variables
  // ............................................................................
  private final static boolean CHECKVERIFIER = true;

  private int id;

  private BigInteger sig;

  private Verifier sigVerifier;

  // Constructors
  // ............................................................................
  public SigShare(final int id, final BigInteger sig, final Verifier sigVerifier) {
    this.id = id;
    this.sig = sig;
    this.sigVerifier = sigVerifier;
  }

  public SigShare(final int id, final byte[] sig) {
    this.id = id;
    this.sig = new BigInteger(sig);
  }

  // Public Methods
  // ............................................................................

  /**
   * Return this share's id. Needed for Lagrange interpolation
   * 
   * @return the id of this key share
   */
  public int getId() {
    return this.id;
  }

  /**
   * Return a BigInteger representation of this signature
   * 
   * @return a BigInteger representation of this signature
   */
  public BigInteger getSig() {
    return this.sig;
  }

  /**
   * Return this signature's verifier
   * 
   * @return A verifier for this signaute
   */
  public Verifier getSigVerifier() {
    return this.sigVerifier;
  }

  /**
   * Return a byte array representation of this signature
   * 
   * @return a byte array representation of this signature
   */
  public byte[] getBytes() {
    return this.sig.toByteArray();
  }

  @Override
  public String toString() {
    return "Sig[" + id + "]: " + sig.toString();
  }

  // Static methods
  // ............................................................................
  public static boolean verify(final byte[] data, final SigShare[] sigs,
      final int k, final int l, final BigInteger n, final BigInteger e)
      throws ThresholdSigException {
    // Sanity Check - make sure there are at least k unique sigs out of l
    // possible

    final boolean[] haveSig = new boolean[l];
    for (int i = 0; i < k; i++) {
      // debug("Checking sig " + sigs[i].getId());
      if (sigs[i] == null)
        throw new ThresholdSigException("Null signature");
      if (haveSig[sigs[i].getId() - 1])
        throw new ThresholdSigException("Duplicate signature: "
            + sigs[i].getId());
      haveSig[sigs[i].getId() - 1] = true;
    }

    final BigInteger x = (new BigInteger(data)).mod(n);
    final BigInteger delta = SigShare.factorial(l);

    // Test the verifier of each signature to ensure there are
    // no dummy sigs thrown in to corrupt the batch
    if (CHECKVERIFIER) {
      final BigInteger FOUR = BigInteger.valueOf(4l);
      final BigInteger TWO = BigInteger.valueOf(2l);
      final BigInteger xtilde = x.modPow(FOUR.multiply(delta), n);

      try {
        final MessageDigest md = MessageDigest.getInstance("SHA");

        for (int i = 0; i < k; i++) {
          md.reset();
          final Verifier ver = sigs[i].getSigVerifier();
          final BigInteger v = ver.getGroupVerifier();
          final BigInteger vi = ver.getShareVerifier();

          // debug("v :" + v);
          md.update(v.toByteArray());

          // debug("xtilde :" + xtilde);
          md.update(xtilde.toByteArray());

          // debug("vi :" + vi);
          md.update(vi.toByteArray());

          final BigInteger xi = sigs[i].getSig();
          // debug("xi^2 :" + xi.modPow(TWO,n));
          md.update(xi.modPow(TWO, n).toByteArray());

          final BigInteger vz = v.modPow(ver.getZ(), n);

          final BigInteger vinegc = vi.modPow(ver.getC(), n).modInverse(n);
          // debug("v^z*v^-c :" + vz.multiply(vinegc).mod(n));
          md.update(vz.multiply(vinegc).mod(n).toByteArray());

          final BigInteger xtildez = xtilde.modPow(ver.getZ(), n);

          // TODO: CHECK PAPER!
          final BigInteger xineg2c = xi.modPow(ver.getC(), n).modInverse(n);
          // According to Shoup, pg. 8 this should be:
          // xi.modPow(TWO,n).modPow(ver.getC(),n).modInverse(n);

          // Something to do with working in Q_n since every
          // element is a square

          // debug("xi^-2cx: " + xineg2c.multiply(xtildez).mod(n));
          md.update(xineg2c.multiply(xtildez).mod(n).toByteArray());
          final BigInteger result = new BigInteger(md.digest()).mod(n);

          if (!result.equals(ver.getC())) {
            debug("Share verifier is not OK");
            return false;
          }
        }
      } catch (final java.security.NoSuchAlgorithmException ex) {
        debug("Provider could not locate SHA message digest .");
        ex.printStackTrace();
      }
    }

    BigInteger w = BigInteger.valueOf(1l);

    for (int i = 0; i < k; i++)
      w = w.multiply(sigs[i].getSig().modPow(
          SigShare.lambda(sigs[i].getId(), sigs, delta), n));

    // eprime = delta^2*4
    final BigInteger eprime = delta.multiply(delta).shiftLeft(2);

    w = w.mod(n);
    final BigInteger xeprime = x.modPow(eprime, n);
    final BigInteger we = w.modPow(e, n);
    return (xeprime.compareTo(we) == 0);
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

  /**
   * Compute lagarange interpolation points Reference: Shoup, pg 7.
   * 
   * @param p -
   *          a polynomial to evaluate these points on
   * @param ik -
   *          a point in S
   * @param S -
   *          a set of k points in {0...l}
   * @param delta -
   *          the factorial of the group size
   * 
   * @return the Lagarange interpolation of these points at 0
   */
  private static BigInteger lambda(final int ik, final SigShare[] S,
      final BigInteger delta) {
    // lambda(id,l) = PI {id!=j, 0<j<=l} (i-j')/(id-j')
    BigInteger value = delta;

    for (final SigShare element : S)
      if (element.getId() != ik)
        value = value.multiply(BigInteger.valueOf(element.getId()));

    for (final SigShare element : S)
      if (element.getId() != ik)
        value = value.divide(BigInteger.valueOf((element.getId() - ik)));

    return value;
  }

  // Debugging
  // ............................................................................
  private static void debug(final String s) {
    System.err.println("SigShare: " + s);
  }

}
