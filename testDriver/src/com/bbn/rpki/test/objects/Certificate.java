/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.util.Calendar;
import java.util.Map;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Certificate extends CA_Obj {

  // Fields

  /** serial */
  public final int serial;

  /** notBefore */
  public final Calendar notBefore;

  /** notAfter */
  public final Calendar notAfter;

  /** subjkeyfile */
  public final String subjkeyfile;

  /** ski */
  public final String ski;

  /** aki */
  public final String aki;

  /** sia */
  public String sia;

  /** SIA_path */
  public String SIA_path;

  /** issuer */
  public String issuer;

  /** subject */
  public String subject;

  /** parentkeyfile */
  public String parentkeyfile;

  /** as_list */
  public IPRangeList as_list;

  /** ipv4 */
  public IPRangeList ipv4;

  /** ipv6 */
  public IPRangeList ipv6;

  Certificate(CA_Object parent,
              final long validityStartTime,
              final long validityEndTime,
              final String dirPath,
              final String nickname,
              final String siaPath,
              IPRangeList asList,
              IPRangeList ipv4,
              IPRangeList ipv6,
              String subjKeyFile,
              String...xargs) {
    super(xargs);
    this.serial = parent == null ? 0 : parent.getNextChildSN();

    // Certificate lifetime and expiration info
    this.notBefore = Calendar.getInstance();
    this.notAfter = Calendar.getInstance();
    notBefore.setTimeInMillis(validityStartTime);
    notAfter.setTimeInMillis(validityEndTime);

    // Set our subject key file name and generate the key
    // Also create the directory it if it doesn't exist
    String keyDirPath = KEYS_PATH + siaPath;
    new File(keyDirPath).mkdirs();
    this.subjkeyfile = keyDirPath + nickname + ".p15";

    // Subject key pair is either (in order of priority)...
    // 1) pre-specified for this certificate
    // 2) pre-specified for this factory (e.g. IANA, maybe RIRs)
    // 3) generated
    if (subjKeyFile != null) {
      Util.copyfile(subjKeyFile, this.subjkeyfile);
      if (DEBUG_ON) {
        System.out.println("Copying pre-specified key file: " + subjKeyFile +
                           " to " + this.subjkeyfile);
      }
    } else {
      String pregeneratedKeyFileName = PregeneratedKeys.getPregeneratedKey();
      if (pregeneratedKeyFileName != null) {
        Util.copyfile(pregeneratedKeyFileName, this.subjkeyfile);
        if (DEBUG_ON) {
          System.out.println("Using pre-generated key for " + this.subjkeyfile);
        }
      } else {
        Util.exec("gen_key", false, false, null,
                  null,
                  null,
                  "../../cg/tools/gen_key", this.subjkeyfile, "2048");
        if (DEBUG_ON) {
          System.out.println("Creating new key for " + this.subjkeyfile);
        }
      }
    }
    // Generate our ski by getting the hash of the public key
    // Result from .p15 -> hash(public_key) which is a hex string
    this.ski = Util.generate_ski(this.subjkeyfile);
    if (DEBUG_ON) {
      System.out.println(this.ski);
    }

    // Create the output file directory if it doesn't exist
    this.outputfilename = dirPath + Util.b64encode_wrapper(this.ski) + ".cer";
    if (DEBUG_ON) {
      System.out.println("outputfilename = " + this.outputfilename);
    }

    new File(dirPath).mkdirs();

    // Initialization based on if you're a TA or not
    // EE and CA else SS
    if (parent != null) {
      this.issuer = parent.commonName;
      this.subject = parent.commonName + "." + nickname;
      Certificate parentCert = parent.getCertificate();
      this.parentkeyfile = parentCert.subjkeyfile;
      this.aki = parentCert.ski;
    } else {
      this.issuer = nickname;
      this.subject = nickname;
      this.parentkeyfile = this.subjkeyfile;
      this.aki = this.ski;
    }
    this.ipv4 = new IPRangeList(ipv4);
    this.ipv6 = new IPRangeList(ipv6);
    this.as_list = new IPRangeList(asList);
  }

  /**
   * @see com.bbn.rpki.test.objects.CA_Obj#getFieldMap(java.util.Map)
   */
  @Override
  public void getFieldMap(Map<String, Object> map) {
    super.getFieldMap(map);
    map.put("serial", serial);
    map.put("notBefore", notBefore);
    map.put("notAfter", notAfter);
    map.put("subjkeyfile", subjkeyfile);
    map.put("ski", ski);
    map.put("aki", aki);
    map.put("sia", sia);
    map.put("SIA_path", SIA_path);
    map.put("issuer", issuer);
    map.put("subject", subject);
    map.put("parentkeyfile", parentkeyfile);
    map.put("as_list", as_list);
    map.put("ipv4", ipv4);
    map.put("ipv6", ipv6);
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public void appendString(StringBuilder sb) {
    sb.append(String.format("%s(%s)", getClass().getSimpleName(), subject));
  }

  /**
   * @return true if the current time is after the validity end time
   */
  public boolean hasExpired() {
    return Clock.now() > notAfter.getTimeInMillis();
  }
}
