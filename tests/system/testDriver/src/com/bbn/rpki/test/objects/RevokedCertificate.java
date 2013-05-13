/*
 * Created on Oct 18, 2012
 */
package com.bbn.rpki.test.objects;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public class RevokedCertificate {
  private final Certificate certificate;
  private final long revocationTime;

  public RevokedCertificate(Certificate certificate) {
    this.certificate = certificate;
    this.revocationTime = Clock.now();
  }

  /**
   * @return the certificate
   */
  public Certificate getCertificate() {
    return certificate;
  }

  /**
   * @return the revocationTime
   */
  public long getRevocationTime() {
    return revocationTime;
  }
}
