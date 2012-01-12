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

    /** commonName */
  public String commonName;

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

  Certificate(CA_Object parent, FactoryBase myFactory, String siaPath, int serial, IPRangeList ipv4,
              IPRangeList ipv6, IPRangeList asList, String subjKeyFile) {
    this.serial = serial;
    String nickname = myFactory.bluePrintName + "-" + this.serial;

    // Certificate lifetime and expiration info
    this.notBefore = Calendar.getInstance();
    this.notAfter = Calendar.getInstance();
    notAfter.setTimeInMillis(notBefore.getTimeInMillis());
    this.notAfter.add(Calendar.DATE, myFactory.ttl);
    
    // Set our subject key file name and generate the key
    // Also create the directory it if it doesn't exist
    String dirPath = KEYS_PATH + siaPath;
    new File(dirPath).mkdirs();
    this.subjkeyfile = dirPath + nickname + ".p15";
    
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
    } else if (myFactory.subjKeyFile != null) {
      Util.copyfile(myFactory.subjKeyFile, this.subjkeyfile);
        if (DEBUG_ON) {
            System.out.println("Copying factory pre-specified key file: " + 
                  myFactory.subjKeyFile + " to " + this.subjkeyfile);
        }
    } else {
        String pregeneratedKeyFileName = PregeneratedKeys.getPregeneratedKey();
        if (pregeneratedKeyFileName != null) {
          Util.copyfile(pregeneratedKeyFileName, this.subjkeyfile);
          if (DEBUG_ON) {
            System.out.println("Using pre-generated key for " + this.subjkeyfile);
          }
        } else {
          Util.exec("gen_key", false, null, null, 
                    null,
                    "../../cg/tools/gen_key",
                    this.subjkeyfile, "2048");
          if (DEBUG_ON) {
            System.out.println("Creating new key for " + this.subjkeyfile);
          }
        }
    }
    // Generate our ski by getting the hash of the public key 
    // Result from .p15 -> hash(public_key) which is a hex string
    this.ski = Util.generate_ski(this.subjkeyfile);
    if (DEBUG_ON)
        System.out.println(this.ski);

    // Set the name we will write to file depending on if
    // this is a CA_cert, EE_cert, SS_cert. Also check if it exists
    if (this instanceof CA_cert) {
        dirPath  = REPO_PATH + parent.SIA_path;
    } else if (this instanceof EE_cert) {
      dirPath = REPO_PATH + "EE/" + parent.SIA_path;
    } else if (this instanceof SS_cert) {
        dirPath = REPO_PATH + myFactory.serverName + "/";
    }
    // Create the output file directory if it doesn't exist
    this.outputfilename = dirPath + Util.b64encode_wrapper(this.ski) + ".cer";
    if (DEBUG_ON) 
        System.out.println("outputfilename = " + this.outputfilename);
    
    new File(dirPath).mkdirs();
    
    // Initialization based on if you're a TA or not
    // EE and CA else SS
    if (parent != null) {
        this.issuer = parent.commonName;
        this.subject = parent.commonName + "." + nickname;
        this.parentkeyfile = parent.certificate.subjkeyfile;
        this.aki = parent.certificate.ski;
        this.ipv4 = new IPRangeList(ipv4);
        this.ipv6 = new IPRangeList(ipv6);
        this.as_list = new IPRangeList(asList);
    } else {
        this.issuer = nickname;
        this.subject = nickname;
        this.parentkeyfile = this.subjkeyfile;
        this.aki = this.ski;
        this.ipv4 = myFactory.getIPV4RangeList();
        this.ipv6 = myFactory.getIPV6RangeList();
        this.as_list = myFactory.getASRangeList();
    }
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
    map.put("commonName", commonName);
    map.put("issuer", issuer);
    map.put("subject", subject);
    map.put("parentkeyfile", parentkeyfile);
    map.put("as_list", as_list);
    map.put("ipv4", ipv4);
    map.put("ipv6", ipv6);
  }
}
