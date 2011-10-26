package threshsig;

/**
 *	Safe Prime Generation
 * 
 * 	Created on November 8, 2001 11:25 AM
 *
 * 	Copyright (C) 2001  Uwe Guenther  <uwe@cscc.de >
 *	Extracted from jhbci Service Provider.
 *
 * 	This is free software; you can redistribute it and/or
 * 	modify it under the terms of the GNU Lesser General Public
 * 	License as published by the Free Software Foundation; either
 * 	version 2.1 of the License, or (at your option) any later version.
 *
 * 	This software is distributed in the hope that it will be useful,
 * 	but WITHOUT ANY WARRANTY; without even the implied warranty of
 * 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * 	Lesser General Public License for more details.
 *
 * 	You should have received a copy of the GNU Lesser General Public
 * 	License along with this library; if not, write to the Free Software
 * 	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-13USA
 *
 * @author Uwe Guenther <uwe@cscc.de>
 *
 */

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

class SafePrimeGen {

  /*
   * First we declare all Stuff needed for logging with java.util.logging.*
   */

  /** The logger for this class. */
  private static final Logger log = Logger.getLogger(SafePrimeGen.class
      .getName());

  /**
   * Default for the certainty.
   * 
   * This value tells a BigInteger constructor the probability of errors for the
   * constructor internal prime test in the form 2^-certainty, or you can say
   * the probability a prime number exceeds 1-1/2^certainty.
   * 
   * @see #generateStrongPrime(int)
   */
  private static final int certainty = 101;

  /**
   * Generates random strong primes.
   * 
   * <p>
   * This menthod generates random strong primes with a given
   * <code>bitLength</code>.
   * 
   * @param bitLength
   *          The bit length that the returned strong prime should have.
   * @return the strong prime with the given <code>bitLength</code>.
   */
  public static BigInteger generateStrongPrime(final int bitLength,
      final SecureRandom random) {
    /*
     * We use the following member in this method:
     * 
     * 1. <code> random </code> the PRNG 2. <code> certainty </code> the default
     * for the certainty.
     * 
     * Note: We use no expliziet this reference in this method. That makes the
     * code clear and readable.
     * 
     * The method is a private helper method of <code> generateKeyPair() </code>
     * to generate random strong primes with a given <code> bitLength </code> .
     * 
     * This method uses DEBUG and INFO log4j statements. DEBUG means a lot of
     * messages. INFO means less highlevel infos. Use log4j.properties file to
     * enable logging.
     * 
     * This method should never hang up. It should always be finite.
     */

    // //////////////////////////////////////////////////////////////////////
    //
    // Gordon's Algorithm for generating strong primes.
    //  
    // see:
    //
    // Strong Primes Are Easy to Find
    // John A. Gordon
    // Lecture Notes in Computer Science 0209, p. 216 ff.
    // http://link.springer.de/link/service/series/0558/bibs/0209/02090216.htm
    //
    //
    // The algorithm is also described in:
    //
    // Handbook of Applied Cryptography by A. Menezes, P. van Oorschot,
    // and S. Vanstone, CRC Press, 1996, chapter 4, page 150.
    // http://www.cacr.math.uwaterloo.ca/hac/
    //
    // We use the steps described in hac for algorithm 4.53. For finer
    // granularity, we split the steps in sub steps such as 1.1, 1.2, ...
    // Also we use the notation used in hac as follows:
    // 
    // p-1 has a large prime factor, denoted r.
    // p+1 has a large prime factor, denoted s.
    // r-1 has a large prime factor, denoted t.
    //
    // Ronald R. Rivest and Robert D. Silverman use in:
    //      
    // Are 'Strong' Primes Needed for RSA?
    // you can find it at ftp://ftp.rsasecurity.com/pub/pdfs/sp2.pdf
    // 
    // the following notation:
    //      
    // p-1 has a large prime factor, denoted p^-.
    // p+1 has a large prime factor, denoted p^+.
    // (p^-)-1 has a large prime factor, denoted p^--.
    //
    // These paper contains a very usefull description for the english words
    // "large prime factor" and how can you interpret large.
    //
    // //////////////////////////////////////////////////////////////////////
    // //////////////////////////////////////////////////////////////////////
    //
    // Step 1 from Gordon's algorithm
    //
    // //////////////////////////////////////////////////////////////////////
    // ////
    // 1.1 Setup the target value for i0.
    // This is the start value where search for prime r with respect in t
    // will start.
    // For details see ftp://ftp.rsasecurity.com/pub/pdfs/sp2.pdf
    // ////
    final int i0BitLengthTargetValue = 12;
    if (log.isLoggable(Level.FINEST))
      log.finest("Have set <i0BitLengthTargetValue=" + i0BitLengthTargetValue
          + ">.");

    // ////
    // 1.2 Setup the target value for j0
    // This is the start value where search for prime p with respect
    // in p0, r, s will start.
    // For details see ftp://ftp.rsasecurity.com/pub/pdfs/sp2.pdf
    // ////
    final int j0BitLengthTargetValue = 12;
    if (log.isLoggable(Level.FINEST))
      log.finest("Have set <j0BitLengthTargetValue=" + j0BitLengthTargetValue
          + ">.");

    // ////
    // 1.3 Setup the bit length for t -- in depence on
    // ftp://ftp.rsasecurity.com/pub/pdfs/sp2.pdf
    // t.bitLength() should be >=
    // ////
    final int tBitLength = bitLength / 2 - i0BitLengthTargetValue;
    if (log.isLoggable(Level.FINEST))
      log.finest("Have calculated <tBitLength=" + tBitLength
          + "> = <bitLength=" + bitLength + ">/2 - <i0BitLengthTargetValue="
          + i0BitLengthTargetValue + ">.");

    // ////
    // 1.4 Generate new BigInteger t -- the large prime factor t
    // of the large primefactor r of p-1. Rivest denotes t in his
    // paper ftp://ftp.rsasecurity.com/pub/pdfs/sp2.pdf as p^-- and
    // r as p^- .
    // ////
    final BigInteger t = new BigInteger(tBitLength, certainty, random);
    if (log.isLoggable(Level.FINER))
      log
          .finer("Have generated large prime factor <t> with bit length <t.bitLength()="
              + t.bitLength() + ">, <t=" + t + ">.");

    // //////////////////////////////////////////////////////////////////////
    //
    // Step 2 from Gordon's algorithm
    //
    // //////////////////////////////////////////////////////////////////////

    // ////
    // 2.1 Setup the bit length for i0. i0BitLength should be equal or very
    // close to i0BitLengthTargetValue.
    // ////
    final int i0BitLength = bitLength / 2 - t.bitLength();
    if (log.isLoggable(Level.FINEST))
      log.finest("Have calculated <i0BitLength=" + i0BitLength
          + "> = <bitLength=" + bitLength + ">/2 - <t.bitLength()="
          + t.bitLength() + ">.");

    // ////
    // 2.2 Setup i0 as a "i0BitLength" bit value. Say the rightmost bit will
    // be denoted as bit 1, the left neighbor of bit 1 as bit 2 and so on...
    // Then all bits will be 0 and the i0bitLength bit will be 1. So
    // we have aBigInteger that will be "i0BitLength" bits long.
    // ////
    final BigInteger i0 = new BigInteger("0").setBit(i0BitLength - 1);
    if (log.isLoggable(Level.FINEST))
      log.finest("Have set <i0> with <i0.bitLength()=" + i0.bitLength()
          + ">, <i0=" + i0 + ">.");

    // ////
    // 2.3 References that are used for provisional results.
    // ////
    BigInteger a;
    BigInteger b;
    BigInteger c;
    BigInteger d;

    // ////
    // 2.4 a is the intermediate result for (t * 2). Now we can use a in the
    // loop. Instead we are calculating 2 * i * t + 1, we use a * i + 1.
    // ////
    a = t.multiply(ThreshUtil.TWO); // a = t * 2

    // ////
    // 2.5 Declare reference that will be used to hold the result for r.
    // ////
    BigInteger r;

    // ////
    // 2.6 Setup i with the start value i0.
    // ////
    BigInteger i = i0;
    if (log.isLoggable(Level.FINEST))
      log.finest("Have set <i=" + i + "> with <i0> as start value for loop 1.");

    // ////
    // 2.7 Loop 1
    // Find r in the sequence 2 * i * t + 1, for i = i0, i0+1, i0+2, ...
    // r = 2 * i * t +
    // ////
    do {
      b = a.multiply(i); // b = a * i --> b = 2 * i * t
      r = b.add(ThreshUtil.ONE); // r = b + --> r = 2 * i * t + 1
      i = i.add(ThreshUtil.ONE); // increment i --> i = i + 1
      if (log.isLoggable(Level.FINEST))
        log.finest("Try to find <r> in <2 * " + i
            + " * t + 1> in loop 1, with bit length <r.bitLength()="
            + r.bitLength() + ">, where <r=" + r + ">.");
    } while (r.isProbablePrime(certainty) == false); // if r is prime we
    // leave
    // the loop

    if (log.isLoggable(Level.FINER))
      log.finer("Have found <r> as probable prime in <2 * " + i
          + " * t + 1> in " + "loop 1, with bit length <r.bitLength()="
          + r.bitLength() + ">, where <r=" + r + ">.");

    // //////////////////////////////////////////////////////////////////////
    //
    // Step 3 from Gordon's algorithm
    //
    // //////////////////////////////////////////////////////////////////////

    // ////
    // 3.1 Declare reference that will be used to hold the result for p.
    // ////
    BigInteger p = null;

    // ////
    // 3.2 Loop 2
    // We loop this outerloop until we have found a matching p
    // depend on random s with respect to random t. For further details see
    // step 4.8.
    // ////
    outerloop: do {
      // ////
      // 3.3 Setup the bit length for s -- in depence on
      // ftp://ftp.rsasecurity.com/pub/pdfs/sp2.pdf
      // s.bitLength() should be >= 130
      // ////
      final int sBitLength = bitLength - r.bitLength() - j0BitLengthTargetValue;
      if (log.isLoggable(Level.FINEST))
        log
            .finest("Have set <sBitLength=bitLength-r.bitLength()-j0BitLengthTargetValue>, "
                + "where <sBitLength=" + sBitLength + ">.");

      // ////
      // 3.4 Generate new BigInteger s -- the large prime factor s of
      // p+1.
      // Rivest denotes s in his paper
      // ftp://ftp.rsasecurity.com/pub/pdfs/sp2.pdf as p^+ .
      // ////
      final BigInteger s = new BigInteger(sBitLength, certainty, random);
      if (log.isLoggable(Level.FINER))
        log
            .finer("Have generated large prime factor <s> with bit length <s.bitLength()="
                + s.bitLength() + ">, <s=" + s + ">.");

      // ////
      // 3.5 Declare reference that will be used to hold the result
      // for p0.
      // ////
      BigInteger p0;

      // ////
      // 3.6 Compute p0 = 2 * (s^(r-2) mod r) * s - 1
      // ////
      a = s.multiply(ThreshUtil.TWO); // a = s * 2
      b = r.subtract(ThreshUtil.TWO); // b = r - 2
      c = s.modPow(b, r); // c = s^b mod r --> s^(r-2) mod r
      d = c.multiply(a); // d = c * a --> 2 * (s^(r-2) mod r) * s
      p0 = d.subtract(ThreshUtil.ONE); // p0 = d - 1 --> 2 * (s^(r-2) mod r) *
      // s - 1
      if (log.isLoggable(Level.FINEST))
        log
            .finest("Have calculated <p0=(s^(r-2) mod r) * s - 1>, with bit length <p0.bitLength()="
                + p0.bitLength() + ">, where <p0=" + p0 + ">.");

      // //////////////////////////////////////////////////////////////////////
      //
      // Step 4 from Gordon's algorithm
      //
      // //////////////////////////////////////////////////////////////////////

      // ////
      // 4.1 b is the intermediate result for (2 * r * s). Now we can
      // use
      // "a"
      // in loop 3. Instead we are calculating p0 + 2 * j * r * s,
      // we use p0 + a * j
      // ////
      a = ThreshUtil.TWO.multiply(r).multiply(s); // a = 2 * r * s

      // ////
      // 4.2 What we are doing here? We calculate an optimal value for
      // j0,
      // so that we can start searching p
      // at 2^(bitLength-1) to (2^bitLength)-1. This means we search
      // the
      // whole range for the target value p. For a example say the
      // target
      // bit length for p should be 6. We set the bit six count from
      // right
      // to left, starting at 1 to 1 like this -> 100000 we reconvert
      // the
      // formula:
      //      
      // p = p0 + 2*j*r*s
      //
      // to
      //  
      // j = (p-p0) / (2*r*s)
      //
      // now we set p = 2^(bitLength-1) and calculate j with our
      // special p,
      // and the already calculated values p0, r, s. Now we add 1 to j
      // to
      // compensate the integer division. So that j will be:
      //
      // j = (2^(bitLength-1) - p0) / (2*r*s) + 1
      //
      // So now we can start searching p starting with a usefull
      // value,
      // means 2^(bitLength-1). This algorithm was my idea!!! ;-)
      // ////
      b = BigInteger.valueOf(0L).setBit(bitLength - 1).subtract(p0); // b =
      // 2^(bitLength-1)
      // - p0
      c = ThreshUtil.TWO.multiply(r).multiply(s); // c =
      // 2*r*s
      BigInteger j0 = b.divide(c); // j0 =
      // b/c
      // --> p
      // - p0 /
      // 2*r*s
      // ////
      // 4.4 Test if (2^(bitLength-1)-p0) isn't a multiple of (2*r*s).
      // If it is, do nothing.
      // If it isn't add one to j0, so that j0 will be the first
      // usefull
      // value to calculate a p that will be bitLength bits long.
      // ////
      if (b.mod(c).equals(ThreshUtil.ZERO) == false) {

        j0 = j0.add(BigInteger.ONE); // (p-p0 / 2*r*s) + 1 -->
        // j0++
        if (log.isLoggable(Level.FINEST))
          log
              .finest("Have incremented <j0>, "
                  + "because <BigInteger.valueOf(0L).setBit(bitLength-1).subtract(p0)> "
                  + "was not a multiple of <TWO.multiply(r).multiply(s)>, "
                  + "where <bitLength=" + bitLength + ">.");
      }
      if (log.isLoggable(Level.FINEST))
        log.finest("Have calculated the the first useful value for "
            + "<j0.bitLength()=" + j0.bitLength() + ">, <j0=" + j0 + ">.");

      // ////
      // 4.6 Setup j with the start value j0.
      // ////
      BigInteger j = j0;
      if (log.isLoggable(Level.FINEST))
        log.finest("Have set <j=" + j
            + "> with <j0> as start value for loop 3.");

      // ////
      // 4.7 Loop 3
      // The innerloop serches for valid p in the range between
      // 2^(bitLength-1) to (2^bitLength)-1. If we walk behind the
      // upper
      // boarder (2^bitLength)-1, we will break the innerloop and
      // continues with the outerloop.
      // ////
      // Innerloop:
      do {
        p = a.multiply(j).add(p0); // p = a * j + p0 --> p = p0
        // + 2 * j *
        // r * s
        if (log.isLoggable(Level.FINEST))
          log.finest("Try to find <p> in <p0 + 2 * " + j
              + " * r * s> in loop 3, " + "with bit length <p.bitLength()="
              + p.bitLength() + ">, " + "where <p=" + p + ">.");

        j = j.add(BigInteger.ONE); // increment j --> j = j + 1

        // ////
        // 4.8. If we walk through the whole range between
        // 2^(bitLength-1)
        // to (2^bitLength)-1. We are going to create new random
        // s, than
        // calc a new p0 from the new random s, and try it again
        // to find
        // a p that matches to the first generated random t. We
        // do this
        // until we find a valid bit in the range between
        // 2^(bitLength-1)
        // to (2^bitLength)-1, in the hope there will be a p at
        // any
        // time. ;-). If there never a valid p will come we run
        // in to a
        // infinite loop. :( , but this should not happend.
        // ////
        if (p.bitLength() > bitLength) {
          if (log.isLoggable(Level.FINEST))
            log.finest("Bit length <p.bitLength()=" + p.bitLength()
                + "> > <bitLength=" + bitLength
                + ">, therefore we continue with loop 2.");
          continue outerloop;
        }

        // ////
        // Break condition for our innerloop.
        // ////
      } while (p.isProbablePrime(certainty) == false);

      if (log.isLoggable(Level.FINER))
        log.finer("Have found <p> as probable strong prime <p0 + 2 * " + j
            + " * r * s> in loop 3, with bit length <p.bitLength()="
            + p.bitLength() + ">, where <p=" + p + ">.");

      // ////
      // Break condition for our outer loop.
      // ////
    } while (p.bitLength() != bitLength);

    if (log.isLoggable(Level.FINEST))
      log.finest("Have left loop 2, because <p.bitLength()=" + p.bitLength()
          + "> == <bitLength=" + bitLength + ">");

    if (log.isLoggable(Level.FINER))
      log.finer("Return from generateStrongPrime(<bitLength=.....>) "
          + "with bit length <p.bitLength()=" + p.bitLength() + ">, <p=" + p
          + ">.");
    // ////
    // At this point p has a valid bit length.
    // ////
    return p;
  }

}
