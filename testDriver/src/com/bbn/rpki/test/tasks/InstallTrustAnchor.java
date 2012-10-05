/*
 * Created on Dec 8, 2011
 */
package com.bbn.rpki.test.tasks;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.bbn.rpki.test.objects.Util;

/**
 * Installs a new trust anchor certificate
 * 
 * Trust anchors are normally delivered by a secure method. This is emulated by
 * simply specifying a local file containing
 * 
 * @author tomlinso
 */
public class InstallTrustAnchor extends TaskFactory {
  protected class Task extends TaskFactory.Task {

    /**
     * @param taskName
     */
    protected Task() {
      super(TASK_NAME);
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory.Task#run()
     */
    @Override
    public void run() {
      File certFile = getCertFile();
      File talFile = model.getTALFile();
      String talPrefix = String.format("%n%s/%s%n", model.getTrustAnchorURL(), certFile.getName());
      try {
        String rawOutput = Util.exec("openssl", false, null, null,
                                     null,
                                     "openssl",
                                     "x509",
                                     "-inform",
                                     "DER",
                                     "-in",
                                     certFile.getPath(),
                                     "-pubkey", "-noout");
        String cookedOutput = Util.exec("awk", false, Util.RPKI_ROOT, rawOutput,
                                        null, "awk", "!/-----(BEGIN|END)/");
        Writer talWriter = new FileWriter(talFile);
        talWriter.write(talPrefix);
        talWriter.write(cookedOutput);
        talWriter.close();

        Util.exec("updateTA", false, Util.RPKI_ROOT, null,
                  null,
                  "run_scripts/updateTA.py",
                  "--verbose", talFile.getPath());
        model.addTrustAnchor(certFile);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    /**
     * @see com.bbn.rpki.test.tasks.TaskFactory#getLogDetail()
     */
    @Override
    protected String getLogDetail() {
      return getCertFile().toString();
    }
  }

  private static final String TASK_NAME = "";

  /**
   * @param model
   */
  public InstallTrustAnchor(Model model) {
    super(model);
  }

  /**
   * @see com.bbn.rpki.test.tasks.TaskFactory#appendBreakdowns(java.util.List)
   */
  @Override
  public void appendBreakdowns(List<Breakdown> list) {
    // There are no breakdowns
  }

  @Override
  protected Task reallyCreateTask(String taskName) {
    assert TASK_NAME.equals(taskName);
    return new Task();
  }

  @Override
  protected Collection<String> getRelativeTaskNames() {
    return Collections.singleton(TASK_NAME);
  }

  /**
   * @return
   */
  public File getCertFile() {
    return model.getTrustAnchorCert();
  }
}
