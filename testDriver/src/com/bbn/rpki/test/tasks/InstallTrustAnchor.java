/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

import com.bbn.rpki.test.objects.Util;

/**
 * Installs a new trust anchor certificate
 * 
 * Trust anchors are normally delivered by a secure method. This is emulated by
 * simply specifying a local file containing
 * 
 * @author tomlinso
 */
public class InstallTrustAnchor extends Task {
  private final File certFile;

  private final File talFile;

  private final String talPrefix;

  /**
   * @param model 
   */
  public InstallTrustAnchor(Model model) {
    this.certFile = model.getTrustAnchorCert();
    this.talFile = model.getTALFile();
    this.talPrefix = String.format("%n%s/%s%n", model.getTrustAnchorURL(), certFile.getName());
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run() {
    try {
      String[] opensslCmd = {
          "openssl",
          "x509",
          "-inform",
          "DER",
          "-in",
          certFile.getPath(),
          "-pubkey",
          "-noout"
      };
      String rawOutput = Util.exec(opensslCmd, "openSSL", false, null, null);
      String[] awkCmd = {"awk", "!/-----(BEGIN|END)/"};
      String cookedOutput = Util.exec(awkCmd, "awk", false, null, rawOutput);
      Writer talWriter = new FileWriter(talFile);
      talWriter.write(talPrefix);
      talWriter.write(cookedOutput);
      talWriter.close();
      
      String[] cmd = {
          "run_scripts/updateTA.py",
          "--verbose",
          talFile.getPath()
      };
      Util.exec(cmd, "updateTA.py", false, null, null);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount() {
    return 0;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int n) {
    assert false;
    return null;
  }
}
