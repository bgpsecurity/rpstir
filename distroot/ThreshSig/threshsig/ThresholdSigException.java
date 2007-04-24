package threshsig;

/**
 * Threshold Signature Exception. Only thrown by Dealer.
 */
public class ThresholdSigException extends RuntimeException {
  private static final long serialVersionUID = 2266413730951237508L;

  protected static String diagnostic = "Threshold Signature Exception";

  public ThresholdSigException() {
    super(diagnostic);
  }

  public ThresholdSigException(final String detail) {
    super(diagnostic + ": " + detail);
  }
}
