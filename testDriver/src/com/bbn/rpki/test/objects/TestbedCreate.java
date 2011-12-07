/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;

import org.ini4j.Profile.Section;
import org.ini4j.Wini;

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

  // Globals for repository specified by configuration file
  // These are set once while parsing the .ini
  private static int MAX_DEPTH;
  private static int MAX_NODES;
  private static Map<String, FactoryBase> FACTORIES;
  
  /**
   * @param args
   */
  public static void main (String...args) {
    String encoded = Util.b64encode_wrapper("0x112CBAA71CAE782E7AB4F49DC93CFEB8AC238249");
    assert "ESy6pxyueC56tPSdyTz-uKwjgkk".equals(encoded);
    String fileName = "test.ini";
    if (args.length > 0) {
      fileName = args[0];
    }
    FACTORIES = new TreeMap<String, FactoryBase>();
    configuration_parser(FACTORIES, fileName);
    IANAFactory ianaFactory = (IANAFactory) FACTORIES.get("IANA");
    ianaFactory.ipv4List.add(Range.createPrefix("0", 0, IPRangeType.ipv4));
    ianaFactory.ipv6List.add(Range.createPrefix("0", 0, IPRangeType.ipv6));
    ianaFactory.asList.add(Range.createRange("0", "0xffffffff", IPRangeType.as));
    removeDirContents(new File(CA_Obj.OBJECT_PATH));
    CA_Object iana = new CA_Object(ianaFactory, null, null);
    create_driver(iana);
}

  /**
   * @param ianaFactory
   */
  private static void create_driver(CA_Object iana) {

    // create our CA queue with no limit and place iana in it
    BlockingDeque<Object> ca_queue = new LinkedBlockingDeque<Object>();
    ca_queue.add(iana);
    // Add a flag to the queue track depth of repository
    String flag = "FLAG - NEW LEVEL";
    ca_queue.add(flag);
    // locals to keep track of where we are in creation
    int repo_depth = 0;
    int repo_size = 1;
    
    // check our conditionals
    while (!(ca_queue.isEmpty()) && (MAX_DEPTH > repo_depth) && MAX_NODES > repo_size) {
        
      Object qItem = ca_queue.removeFirst();

        // Check if this is the start of a new level
        if (qItem == flag) {
            // If we're at the end of the queue already then just break
            if (ca_queue.isEmpty()) {
                break;
            }
            // Otherwise add the flag back into the queue to 
            // track for the next level
            ca_queue.add(flag);
            repo_depth += 1;
            // continue onto the next node in the queue
            continue;
        }
        CA_Object ca_node = (CA_Object) qItem;
        // Create the directory for the objects we're about to store
        String dir_path = REPO_PATH + ca_node.SIA_path;
        if (!new File(dir_path).isDirectory()) {
          new File(dir_path).mkdirs();
        }

        List<CA_Obj> child_list = new ArrayList<CA_Obj>();
        // Creates all child CA's and ROA's for a the CA ca_node
        repo_size = create_children(child_list, ca_node, repo_size);
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
                                        ca_node.myFactory.ttl, 
                                        null);
        Manifest new_manifest = new Manifest(ca_node, eeFactory);
        ca_node.manifests.add(new_manifest);
        repo_size += 1;

        
        // Add all of our children to the queue of CAs
        for (CA_Obj child : child_list) {
            if (child instanceof CA_Object) {
                ca_node.children.add((CA_Object) child);
                ca_queue.add(child);
            } else if (child instanceof Roa) {
                ca_node.roas.add((Roa) child);
            } else {
                System.err.println("Somehow got something besides CA or ROA in child list");
            }
        }
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
  private static int create_children(List<CA_Obj> child_list, CA_Object ca_node, int repo_size) {
    if (DEBUG_ON) System.out.println(ca_node.bluePrintName);
    List<Pair> list = FACTORIES.get(ca_node.bluePrintName).childSpec;
    for (Pair ca_def : list) {
      for (int n = 0; n < ca_def.arg.intValue(); n++) {
        if (MAX_NODES > repo_size) {
          CA_Obj child = FACTORIES.get(ca_def.tag).create(ca_node);
          child_list.add(child);
          repo_size += 1;
          if (DEBUG_ON) System.out.format("Child created. repo_size = %d%n", repo_size);
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
  private static void removeDirContents(File file) {
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
   * Parses the val as a string like AFRINIC,1%APNIC,2%RIPE,2...
   * Stores result as a tuple in the list toMode
   */
  static void parse(List<Pair> toMod, String val) {
    // parse the string like AFRINIC,1%APNIC,2%RIPE,2...
    String[] list = val.split(",");
    for (String item : list) {
      // split the individual groups
      String[] p = item.split("%");
      try {
        Pair pair;
        if (p.length == 1) {
          pair = new Pair(p[0].trim(), null);
        } else {
          pair = new Pair(p[0].trim(), new BigInteger(p[1].trim()));
        }
        toMod.add(pair);
      } catch (Exception e) {
        throw new RuntimeException("Error parsing " + item);
      }
    }
  }

  /**
   * @param factories
   * @param fileName
   */
  private static void configuration_parser(Map<String, FactoryBase> factories, 
                                           String fileName) {

    try {
      // construct the configparser and read in the config file
      Wini config = new Wini(new File(fileName));
      Collection<Map.Entry<String, Section>> sectionEntries = config.entrySet();

      // loop over all sections and options and build factories
      for (Map.Entry<String, Section> sectionEntry : sectionEntries) {
        List<Pair> child = new ArrayList<Pair>();
        List<Pair> ipv4 = new ArrayList<Pair>();
        List<Pair> ipv6 = new ArrayList<Pair>();
        List<Pair> as_list = new ArrayList<Pair>();
        List<Pair> roav4l = new ArrayList<Pair>();
        List<Pair> roav6l = new ArrayList<Pair>();
        int a = 0;
        String server = null;
        boolean breakA = false;
        Integer t = 0;
        String subjkeyfile = null;
        
        String section = sectionEntry.getKey();
        Section sectionMap = sectionEntry.getValue();
        for (Map.Entry<String, String> entry : sectionMap.entrySet()) {

          Option option = Option.valueOf(entry.getKey().toLowerCase());
          if (option == null) {
            System.err.println("Opt in config file not recognized: " + entry.getKey());
            continue;
          }
          String prop = entry.getValue().trim();
          switch (option) {

          case childspec:
            parse(child, prop);
            break;
          case ipv4list:
            parse(ipv4, prop);
            break;
          case ipv6list:
            parse(ipv6, prop);
            break;
          case aslist:
            parse(as_list, prop);
            break;
          case servername:
            server = prop;
            break;
          case breakaway:
            breakA = prop.equalsIgnoreCase("true");
            break;
          case ttl:
            t = new Integer(prop);
            break;
          case max_depth:
            MAX_DEPTH = new Integer(prop);
            break;
          case max_nodes:
            MAX_NODES = new Integer(prop);
            break;
          case roaipv4list:
            parse(roav4l, prop);
            break;
          case roaipv6list:
            // FIXME: maxlength not yet supported
            parse(roav6l, prop);
            break;
          case asid:
            a = new Integer(prop);
            break;
          case subjkeyfile:
            subjkeyfile = prop;
            break;
          }
        }
          String[] typeAndName = section.split("-");
          String type = typeAndName[0];
          String name = typeAndName[1];
          FactoryType factoryType = FactoryType.valueOf(type);
          if (factoryType == null) {
            System.out.println("Unrecognized type included in name of section in the .ini: " + type);
            return;
          }
          FactoryBase f = null;
          switch (factoryType) {
          case C: {
            if ("IANA".equals(name)) {
              f = new IANAFactory(name, child, server, breakA, t, subjkeyfile);
            } else {
              f = new Factory(name, 
                              ipv4,
                              ipv6, 
                              as_list,
                              child,
                              server,
                              breakA,
                              t,
                              subjkeyfile);
            }
            break;
          }
          case M:
            continue;
          case CR:
            continue;
          case R: {
            f = new RoaFactory(name,
                               ipv4,
                               ipv6,
                               as_list, child,
                               server, 
                               breakA,
                               t,
                               roav4l,
                               roav6l, 
                               a);
            break;
          }
          }
                    // Add our bluePrintName to the factory dictionary
          factories.put(name, f);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }    
  }
}
