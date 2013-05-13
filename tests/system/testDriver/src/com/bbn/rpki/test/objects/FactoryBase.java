/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.util.List;

import com.bbn.rpki.test.actions.InitializeAction;
import com.bbn.rpki.test.tasks.Model;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public abstract class FactoryBase<T> {

  /**
   * bp name
   */
  protected String bluePrintName;
  /**
   * time to live in days
   */
  String subjKeyFile;
  String serverName;
  String SIA_path;

  final List<Pair> childSpec;

  protected FactoryBase(String bluePrintName,
                        List<Pair> childSpec,
                        String serverName,
                        String subjKeyFile) {
    this.bluePrintName = bluePrintName;
    this.childSpec = childSpec;
    this.serverName = serverName;
    this.subjKeyFile = subjKeyFile;
  }

  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#create(com.bbn.rpki.test.objects.CA_Object)
   */
  abstract T create(Model model, InitializeAction initializeAction, CA_Object parent, int id);

  /**
   * @return the serverName
   */
  public String getServerName() {
    return serverName;
  }
}
