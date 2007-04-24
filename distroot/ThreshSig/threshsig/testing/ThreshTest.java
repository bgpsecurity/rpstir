package threshsig.testing;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.junit.Before;
import org.junit.Test;

import threshsig.Dealer;
import threshsig.GroupKey;
import threshsig.KeyShare;
import threshsig.SigShare;

public class ThreshTest {
  private static final int keysize = 512;

  private static final int k = 6;

  private static final int l = 13;

  private static Dealer d;

  private static GroupKey gk;

  private static KeyShare[] keys;

  private static final byte[] data = new byte[1024];

  private static byte[] b;

  private static final SigShare[] sigs = new SigShare[k];

  @Before
  public final void setUp() throws NoSuchAlgorithmException {
    (new Random()).nextBytes(data);
    final MessageDigest md = MessageDigest.getInstance("SHA-1");
    b = md.digest(data);
  }

  @Test
  public final void testInitDealer() {
    // Initialize a dealer with a keysize
    d = new Dealer(keysize);

    final long start = System.currentTimeMillis();
    long elapsed;
    // Generate a set of key shares
    d.generateKeys(k, l);

    elapsed = System.currentTimeMillis() - start;
    System.out.println("\tKey Gen total (ms): " + elapsed);

    // This is the group key common to all shares, which
    // is not assumed to be trusted. Treat like a Public Key
    gk = d.getGroupKey();

    // The Dealer has the shares and is assumed trusted
    // This should be destroyed, unless you want to reuse the
    // Special Primes of the group key to generate a new set of
    // shares
    keys = d.getShares();
  }

  @Test
  public void testVerifySignatures() {
    System.out.println("Attempting to verify a valid set of signatures...");
    // Pick a set of shares to attempt to verify
    // These are the indices of the shares
    final int[] S = { 3, 5, 1, 2, 10, 7 };

    for (int i = 0; i < S.length; i++)
      sigs[i] = keys[S[i]].sign(b);

    assertTrue(SigShare
        .verify(b, sigs, k, l, gk.getModulus(), gk.getExponent()));
  }

  @Test
  public void testVerifySignaturesAgain() {
    System.out.println("Attempting to verify a different set of shares...");

    // Create k sigs to verify using different keys
    final int[] T = { 8, 9, 7, 6, 1, 12 };
    for (int i = 0; i < k; i++)
      sigs[i] = keys[T[i]].sign(b);

    assertTrue(SigShare
        .verify(b, sigs, k, l, gk.getModulus(), gk.getExponent()));
  }

  @Test
  public void testVerifyBadSignature() {
    b = "corrupt data".getBytes();
    sigs[3] = keys[3].sign(b);
    assertFalse(SigShare.verify(b, sigs, k, l, gk.getModulus(), gk
        .getExponent()));
  }

  @Test
  public void testPerformance() {
    final int RUNS = 20;
    final int[] S = { 3, 5, 1, 2, 10, 7 };

    long start = System.currentTimeMillis(), elapsed;
    for (int i = 0; i < RUNS; i++)
      sigs[i % k] = keys[S[i % k]].sign(b);
    elapsed = System.currentTimeMillis() - start;
    System.out.println("Signing total (" + RUNS + " sigs) (ms): " + elapsed
        + " Average: " + (float) (elapsed / RUNS));

    for (int i = 0; i < k; i++)
      sigs[i] = keys[S[i]].sign(b);

    start = System.currentTimeMillis();
    for (int i = 0; i < RUNS; i++)
      if (!SigShare.verify(b, sigs, k, l, gk.getModulus(), gk.getExponent()))
        System.out.println("Sig Failed to verify correctly");
    elapsed = System.currentTimeMillis() - start;
    System.out.println("Verification total (" + RUNS + " sigs) (ms): "
        + elapsed + " Average: " + (float) (elapsed / RUNS));
  }
}
