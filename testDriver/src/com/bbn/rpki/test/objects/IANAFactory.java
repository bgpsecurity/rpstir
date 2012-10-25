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
public class IANAFactory extends FactoryBase<CA_Object> {
  /**
   * @param bluePrintName
   * @param childSpec
   * @param serverName
   * @param breakAway
   * @param ttl
   * @param subjKeyFile
   */
  protected IANAFactory(String bluePrintName, List<Pair> childSpec, String serverName,
                        boolean breakAway, int ttl, String subjKeyFile) {
    super(bluePrintName, childSpec, serverName, breakAway, ttl, subjKeyFile);
  }

  /**
   * @see com.bbn.rpki.test.objects.FactoryBase#create(com.bbn.rpki.test.objects.CA_Object, int)
   */
  @Override
  CA_Object create(Model model, InitializeAction initializeAction, CA_Object parent, int id) {
    CA_Object caObject = new CA_Object(this, parent, id, bluePrintName,
                                       serverName,
                                       breakAway);
    return caObject;
  }
}
