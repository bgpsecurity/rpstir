/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;

import com.bbn.rpki.test.actions.ActionManager;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class TestbedCreate implements Constants {
  enum Option {
    childspec,
    ipv4list,
    ipv6list,
    aslist,
    servername,
    breakaway,
    ttl,
    max_depth,
    max_nodes,
    roaipv4list,
    roaipv6list,
    asid,
    subjkeyfile
  }

  enum FactoryType {
    C,
    M,
    CR,
    R
  }

  /**
   * @param args
   */
  public static void main (String...args) {
    String fileName = "test.ini";
    if (args.length > 0) {
      fileName = args[0];
    }
    TestbedConfig testbedConfig = new TestbedConfig(fileName);
    TestbedCreate tbc = new TestbedCreate(testbedConfig);
    tbc.writeFiles();
  }

  private final Map<String, FactoryBase> FACTORIES;
  private final int MAX_DEPTH;
  private final int MAX_NODES;
  private final IANAFactory ianaFactory;
  private final CA_Object iana;

  /**
   * @param testbedConfig
   */
  public TestbedCreate(TestbedConfig testbedConfig) {
    FACTORIES = testbedConfig.getFactories();
    MAX_DEPTH = testbedConfig.getMaxDepth();
    MAX_NODES = testbedConfig.getMaxNodes();
    ianaFactory = (IANAFactory) FACTORIES.get("IANA");
    ianaFactory.ipv4List.add(Range.createPrefix("0", 0, IPRangeType.ipv4));
    ianaFactory.ipv6List.add(Range.createPrefix("0", 0, IPRangeType.ipv6));
    ianaFactory.asList.add(Range.createRange("0", "0xffffffff", IPRangeType.as));
    iana = new CA_Object(ianaFactory, null, 0, ianaFactory.subjKeyFile);
  }

  /**
   * @return the root of the tree (IANA)
   */
  public CA_Object getRoot() {
    return iana;
  }

  /**
   * 
   */
  public void writeFiles() {
    removeDirContents(new File(Constants.OBJECT_PATH));
    create_driver(iana);
    List<CA_Obj> rpkiObjects = new ArrayList<CA_Obj>();
    iana.appendObjectsToWrite(rpkiObjects);
    for (CA_Obj ca_Obj : rpkiObjects) {
      Util.writeConfig(ca_Obj);
      Util.create_binary(ca_Obj);
    }
  }

  /**
   * @param iana
   */
  public void create_driver(CA_Object iana) {

    // create our CA queue with no limit and place iana in it
    Deque<CA_Object> ca_queue = new ArrayDeque<CA_Object>();
    Deque<CA_Object> child_queue = new ArrayDeque<CA_Object>();
    ca_queue.add(iana);
    // locals to keep track of where we are in creation
    int repo_depth = 0;
    int repo_size = 1;

    // check our conditionals
    while (!(ca_queue.isEmpty() && child_queue.isEmpty()) && (MAX_DEPTH > repo_depth) && MAX_NODES > repo_size) {

      Object qItem = ca_queue.poll();
      if (qItem == null) {
        // Queue empty, advance to the next level
        repo_depth++;
        ca_queue.addAll(child_queue);
        child_queue.clear();
        continue;
      }
      CA_Object ca_node = (CA_Object) qItem;

      // Creates all child CA's and ROA's for a the CA ca_node
      repo_size = create_children(ca_node, repo_size);

      child_queue.addAll(ca_node.children);
      // crl_list
      Crl new_crl = new Crl(ca_node);
      ca_node.crl.add(new_crl);
      repo_size += 1;
      // manifest_list
      // create an template factory for our ee needed in the manifest
      Factory eeFactory = new Factory("Manifest-EE",
                                      null,
                                      null,
                                      null,
                                      null,
                                      null,
                                      false,
                                      ca_node.getTtl(),
                                      null);
      Manifest new_manifest = new Manifest(ca_node);
      ca_node.manifests.add(new_manifest);
      repo_size += 1;
    }

    System.out.format("Finished creation driver loop. repo_depth = %d repo_size = %d%n", repo_depth, repo_size);
    System.out.format("MAX_REPO depth %d%n", MAX_DEPTH);
  }

  /**
   * @param child_list
   * @param ca_node
   * @param repo_size
   * @return
   */
  private int create_children(CA_Object ca_node, int repo_size) {
    if (DEBUG_ON) {
      System.out.println(ca_node.bluePrintName);
    }
    List<Pair> list = FACTORIES.get(ca_node.bluePrintName).childSpec;
    for (Pair ca_def : list) {
      for (int n = 0; n < ca_def.arg.intValue(); n++) {
        if (MAX_NODES > repo_size) {
          Object child = FACTORIES.get(ca_def.tag).create(ca_node, ca_node.children.size());
          if (child instanceof CA_Object) {
            CA_Object caChild = (CA_Object) child;
            ActionManager.singleton().recordCA_Object(caChild);
            ca_node.children.add(caChild);
          } else if (child instanceof Roa) {
            ca_node.roas.add((Roa) child);
          } else {
            System.err.println("Somehow got something besides CA or ROA as a child");
          }
          repo_size += 1;
          if (DEBUG_ON) {
            System.out.format("Child created. repo_size = %d%n", repo_size);
          }
        } else {
          return repo_size;
        }
      }
    }
    return repo_size;
  }

  /**
   * @param file
   */
  private void removeDirContents(File file) {
    File[] contents = file.listFiles();
    if (contents != null) {
      for (File sub : contents) {
        if (sub.isDirectory()) {
          removeDirContents(sub);
        }
        sub.delete();
      }
    }
  }

  /**
   * Create all the children
   */
  public void createDriver() {
    create_driver(iana);
  }
}
