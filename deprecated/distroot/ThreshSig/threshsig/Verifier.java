package threshsig;

import java.math.BigInteger;

class Verifier {
  private BigInteger z;

  private BigInteger c;

  private BigInteger groupVerifier;

  private BigInteger shareVerifier;

  public Verifier(final BigInteger z, final BigInteger c,
      final BigInteger shareVerifier, final BigInteger groupVerifier) {
    this.z = z;
    this.c = c;
    this.shareVerifier = shareVerifier;
    this.groupVerifier = groupVerifier;
  }

  public BigInteger getZ() {
    return this.z;
  }

  public BigInteger getShareVerifier() {
    return this.shareVerifier;
  }

  public BigInteger getGroupVerifier() {
    return this.groupVerifier;
  }

  public BigInteger getC() {
    return this.c;
  }
}
