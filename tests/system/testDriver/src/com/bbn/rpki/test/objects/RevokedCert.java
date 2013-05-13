/*
 * Created on Nov 18, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;
import java.util.Date;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class RevokedCert extends Pair {
  /**
   * @param serial
   * @param date
   */
  public RevokedCert(int serial, Date date) {
    super(String.valueOf(serial), BigInteger.valueOf(date.getTime()));
  }
  
  /**
   * @see com.bbn.rpki.test.objects.Pair#toString()
   */
  @Override
  public String toString() {
    return Util.dateToString(new Date(arg.longValue()));
  }
}
