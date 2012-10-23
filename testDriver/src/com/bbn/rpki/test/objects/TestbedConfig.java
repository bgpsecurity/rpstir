/*
 * Created on Dec 9, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.Writer;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.ini4j.Profile.Section;
import org.ini4j.Wini;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TestbedConfig implements Constants {

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

  private final Map<String, FactoryBase<?>> factories = new TreeMap<String, FactoryBase<?>>();
  // Globals for repository specified by configuration file
  // These are set once while parsing the .ini
  private int maxDepth;
  private int maxNodes;
  private Wini wini;

  /**
   * Construct config for the specified file
   * @param iniFile
   */
  public TestbedConfig(String iniFile) {
    Util.deleteDirectories(new File(OBJECT_PATH).listFiles());
    try {
      wini = new Wini(new StringReader(iniFile));
      Collection<Map.Entry<String, Section>> sectionEntries = wini.entrySet();

      // loop over all sections and options and build factories
      for (Map.Entry<String, Section> sectionEntry : sectionEntries) {
        configureFactory(sectionEntry);
        Section section = sectionEntry.getValue();
        for (TestbedCreate.Option option : TestbedCreate.Option.values()) {
          if (!option.keep()) {
            section.remove(option.name());
          }
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Write the config file
   * @param writer
   */
  public void write(Writer writer) {
    try {
      wini.store(writer);
    } catch (IOException e) {
      // Should not happen
    }
  }

  /**
   * @param sectionEntry
   */
  private void configureFactory(Map.Entry<String, Section> sectionEntry) {
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
      TestbedCreate.Option option = TestbedCreate.Option.valueOf(entry.getKey());
      if (option == null) {
        System.err.println("Opt in config file not recognized: " + entry.getKey());
        continue;
      }
      String prop = entry.getValue().trim();
      switch (option) {

      case childSpec:
        parse(child, prop);
        break;
      case ipv4List:
        parse(ipv4, prop);
        break;
      case ipv6List:
        parse(ipv6, prop);
        break;
      case asList:
        parse(as_list, prop);
        break;
      case serverName:
        server = prop;
        break;
      case breakAway:
        breakA = prop.equalsIgnoreCase("true");
        break;
      case ttl:
        t = new Integer(prop);
        break;
      case max_depth:
        maxDepth = new Integer(prop);
        break;
      case max_nodes:
        maxNodes = new Integer(prop);
        break;
      case ROAipv4List:
        parse(roav4l, prop);
        break;
      case ROAipv6List:
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
    TestbedCreate.FactoryType factoryType = TestbedCreate.FactoryType.valueOf(type);
    if (factoryType == null) {
      throw new RuntimeException("Unrecognized type included in name of section in the .ini: " + type);
    }
    FactoryBase<?> f = null;
    switch (factoryType) {
    case C: {
      if ("IANA".equals(name)) {
        f = new IANAFactory(name, child, server, breakA, t, subjkeyfile);
      } else {
        f = new CAFactory(name,
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
      return;
    case CR:
      return;
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

  /**
   * @return the parsed factories map
   */
  public Map<String, FactoryBase<?>> getFactories() {
    return factories;
  }

  /**
   * @return the maxNodes
   */
  public int getMaxNodes() {
    return maxNodes;
  }

  /**
   * @return the maximum depth allowed
   */
  public int getMaxDepth() {
    return maxDepth;
  }

  /**
   * @param nodeName
   * @return the specified factory
   */
  public FactoryBase<?> getFactory(String nodeName) {
    return factories.get(nodeName);

  }

  /**
   * @return all the repository roots
   */
  public Collection<File> getRepositoryRoots() {
    Set<File> ret = new TreeSet<File>();
    for (FactoryBase<?> factoryBase : factories.values()) {
      if (factoryBase.isBreakAway() || factoryBase instanceof IANAFactory) {
        ret.add(new File(new File(REPO_PATH), factoryBase.serverName));
      }
    }
    return ret;
  }
}
