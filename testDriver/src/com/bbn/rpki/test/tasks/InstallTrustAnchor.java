/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import com.bbn.rpki.test.utils.OS;

/**
 * Installs a new trust anchor certificate
 * 
 * Trust anchors are normally delivered by a secure method. This is emulated by
 * simply specifying a local file containing
 * 
 * @author tomlinso
 */
public class InstallTrustAnchor implements Task {
  private final File certFile;

  private final File talFile;

  /**
   * @param certFile
   * @param talFile
   */
  public InstallTrustAnchor(Model model) {
    this.certFile = model.getTrustAnchorCert();
    this.talFile = model.getTALFile();
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#run()
   */
  @Override
  public void run(int epochIndex) {
    if (epochIndex > 0) return;
    try {
      OutputStream talOutputStream = new FileOutputStream(talFile);
      String[] opensslCmd = {
          "openssl",
          "x509",
          "-inform",
          "DER",
          "-in",
          certFile.getPath(),
          "-pubkey",
      "-noout"};
      String[] awkCmd = {"awk", "!/-----(BEGIN|END)/"};
      OS.exec(null, talOutputStream, System.err, opensslCmd, awkCmd);
      
      String[] cmd = {
          "run_scripts/updateTA.py",
          talFile.getPath()
      };
      OS.exec(null, System.out, System.err, cmd);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getBreakdownCount()
   */
  @Override
  public int getBreakdownCount(int epochIndex) {
    return 0;
  }

  /**
   * @see com.bbn.rpki.test.tasks.Task#getTaskBreakdown(int)
   */
  @Override
  public TaskBreakdown getTaskBreakdown(int epochIndex, int n) {
    assert false;
    return null;
  }
}
