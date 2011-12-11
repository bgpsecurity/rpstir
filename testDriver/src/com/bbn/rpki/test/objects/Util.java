/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Util implements Constants {
  private static Runtime runtime = Runtime.getRuntime();
  
  private static final String B64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  private static DateFormat dateFormat1 = new SimpleDateFormat("yyMMddHHmmss'Z'");

  private static DateFormat dateFormat2 = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

  /**
   * The value of the RPKI_ROOT environment variable
   */
  public static File RPKI_ROOT;
  
  static {
    RPKI_ROOT = new File(System.getenv("RPKI_ROOT")).getAbsoluteFile();
  }
  /**
   * @param from
   * @param to
   */
  public static void copyfile(String from, String to) {
    try {
      InputStream is = new FileInputStream(from);
      try {
        OutputStream os = new FileOutputStream(to);
        try {
          byte[] bf = new byte[8192];
          int nb;
          while ((nb = is.read(bf)) > 0) {
            os.write(bf, 0, nb);
          }
        } finally {
          os.close();
        }
      } finally {
        is.close();
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * @param ski2 Bytes encoded as a hex string
   * @return url-safe base64 encoded string
   */
  static String b64encode_wrapper(String ski2) {
    StringBuilder sb = new StringBuilder();
    // Apparently the first two characters are to be ignored.
    ski2 = ski2.substring(2);
    int length = ski2.length();
    assert length % 2 == 0;
    int b = 0;
    int w = 0;
    for (int i = 0; i < length; i++) {
      b <<= 4;
      char c1 = ski2.charAt(i);
      if (c1 <= '9') {
        b |= (c1 - '0');
      } else {
        b |= (c1 - 'A' + 10);
      }
      w += 4;
      if (w >= 6 || i == length - 1) {
        int x = ((b << 6) >> w) & 0x3f;
        sb.append(B64_ALPHABET.charAt(x));
        int mask = 0x3f << (w - 6);
        b &= ~mask;
        w -= 6;
      }
    }
    return sb.toString();
  }
  
  private static StringBuilder appendList(StringBuilder sb, String member, List<?> words) {
   sb.append(member).append("=");
   boolean first = true;
    String sep = ",";
    for (Object word : words) {
      if (first) {
        first = false;
      } else {
        sb.append(sep);
      }
      sb.append(word);
    }
    sb.append(String.format("%n"));
    return sb;
  }

  /**
   * @param ca_obj
   */
  public static void writeConfig(CA_Obj ca_obj) {
    try {
      // Use introspection to print out all the member variables and their values to a file
      File configDir = new File(CA_Obj.CONFIG_PATH);
      if (!configDir.isDirectory())
          configDir.mkdirs();
      File outputFile = new File(ca_obj.outputfilename);
      String name = outputFile.getName();
      String cfgName = CA_Obj.CONFIG_PATH + name + ".cfg";
      Writer f = new FileWriter(cfgName);
      
      // Gets all the attributes of this class that are only member variables(not functions)
      // builds the string to print to the file
      StringBuilder sb = new StringBuilder();
      if (ca_obj instanceof EE_cert) {
          sb.append("type=ee\n");
      } else if (ca_obj instanceof Certificate) {
          sb.append("type=ca\n");
      }

  // loops through all member of this class and writes them to the config file

      Field[] fields = ca_obj.getClass().getFields();
      for (Field field : fields) {
        if (Modifier.isStatic(field.getModifiers())) continue;
        Object val = field.get(ca_obj);
        if (val != null) {
          String member = field.getName();
          if (member.equals("issuer") || member.equals("subject")) {
            // deal with the issuer and subject name
            String[] fieldNames;
            fieldNames = ((String) val).split("%");
            String name2 = fieldNames[0];
            String ser = fieldNames.length < 2 ? null : fieldNames[1];
            if (ser != null) {
              sb.append(String.format("%s=%s%%%s%n", member, name2, ser));
            } else {
              sb.append(String.format("%s=%s%n", member, val));
            }
          } else if (member.equals("as_list")) {
            member = "as";
            IPRangeList rangeList = (IPRangeList) val;
            if (IPRangeList.isInherit(rangeList)) {
              sb.append(String.format("%s=%s%n", member, "inherit"));
            } else {
              appendList(sb, member, rangeList);
            }
          } else if (member.equals("ipv4") || member.equals("ipv6")) {
            IPRangeList range = (IPRangeList) val;
            if (IPRangeList.isInherit(range)) {
              sb.append(String.format("%s=%s%n", member, "inherit"));
            } else {
              appendList(sb, member, range);
            }
          } else if (member.equals("roaipv4") || member.equals("roaipv6")) {
            IPRangeList rangeList = (IPRangeList) val;
            appendList(sb, member, rangeList);
          } else if (member.equals("notBefore") || member.equals("notAfter")) {
            appendDateTime(sb, member, (Calendar) val, true);
          } else if (member.equals("thisupdate") || member.equals("nextupdate")) {
            Calendar cal = (Calendar) val;
            appendDateTime(sb, member, cal, !(ca_obj instanceof Manifest));
          } else if (member.equals("fileList")) {
            @SuppressWarnings("unchecked")
            List<?> list = (List<Object>) val;
            appendList(sb, member, list);
          } else if (member.equals("revokedcertlist")) {
            @SuppressWarnings("unchecked")
            List<?> list = (List<Object>) val;
            appendList(sb, member, list);
          } else {
            sb.append(String.format("%s=%s%n", member, val));
          }
        }
      }
              
      f.write(sb.toString());
      f.close();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

  }

  /**
   * @param sb
   * @param member
   * @param cal
   */
  private synchronized static void appendDateTime(StringBuilder sb, String member, Calendar cal, boolean abbrevYear) {
    if (cal.get(Calendar.YEAR) < 2050 && abbrevYear) {
      sb.append(String.format("%s=%s%n", member, dateFormat1.format(cal.getTime())));
    } else {
      sb.append(String.format("%s=%s%n", member, dateFormat2.format(cal.getTime())));
    }
  }
  
  /**
   * @param date
   * @return String form of date
   */
  public synchronized static String dateToString(Date date) {
    return dateFormat2.format(date);
  }

  /**
   * @param ca_obj 
   * @param xargs 
   * @param string
   */
  public static void create_binary(CA_Obj ca_obj, String... xargs) {
    String[] path = ca_obj.outputfilename.split("/");
    String file = path[path.length - 1];
    String[] cmdArray = new String[3 + xargs.length];
    cmdArray[0] = Constants.BIN_DIR + "/create_object";
    cmdArray[1] = "-f";
    cmdArray[2] = CA_Obj.CONFIG_PATH + file + ".cfg";
    System.arraycopy(xargs, 0, cmdArray, 3, xargs.length);
    exec(cmdArray, "create_object", false, null, null);
  }

  /**
   * @param fileName
   * @return
   */
  static String generate_ski(String fileName) {
    String[] cmdArray = {
        Constants.BIN_DIR + "/gen_hash",
        "-f",
        fileName
    };
    return exec(cmdArray, "gen_hash", true, null, null);
  }

  /**
   * Execute a command in the rpki root directory
   * @param cmdArray
   * @return stdout
   */
  public static String execInRoot(String...cmdArray) {
    return exec(cmdArray, cmdArray[0], true, RPKI_ROOT, null);
  }
  
  /**
   * @param cmdArray
   * @param title
   * @param ignoreStatus TODO
   * @param cwd 
   * @param input TODO
   * @return stdout string
   */
  public static String exec(String[] cmdArray, String title, boolean ignoreStatus, File cwd, String input) {
    int status;
    try {
      if (cwd == null) {
        cwd = new File(System.getProperty("user.dir")).getAbsoluteFile();
      }
      final Process f = runtime.exec(cmdArray, null, cwd);
      Sucker stdout = new Sucker(f.getInputStream(), "stdout", System.out);
      Sucker stderr = new Sucker(f.getErrorStream(), "stderr", System.err);
      if (input != null) {
        OutputStream os = f.getOutputStream();
        Writer writer = new OutputStreamWriter(os);
        writer.write(input);
        writer.close();
      }
      status = f.waitFor();
      stdout.join();
      stderr.join();
      String string = stdout.getString();
      @SuppressWarnings("unused") // For debugging
      String errString = stderr.getString();
      if (DEBUG_ON) {
        System.out.println(Arrays.asList(cmdArray));
        System.out.println(string);
      }
      if (status != 0) {
        String msg = String.format("%s failed status = %d%n", title, status);
        if (ignoreStatus) {
          if (DEBUG_ON) System.out.println(msg);
        } else {
        throw new RuntimeException(msg);
        }
      }
      return string;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Calls the gen_hash C executable and grabs the STDOUT from it
   *  and returns it as the hash of the contents of the filename
   * @param file 
   * @return the hash
   */
  public static String generate_file_hash(File file) {
    {
      String[] cmdArray = {
          Constants.BIN_DIR + "/gen_hash",
          "-n",
          file.getPath()
      };
    return exec(cmdArray, "gen_hash", true, null, null);
    }
  }

  /**
   * @param string
   * @param prefix
   * @return the supplied string with the given prefix removed
   */
  public static String removePrefix(String string, String prefix) {
    assert string.startsWith(prefix);
    return string.substring(prefix.length());
  }

  /**
   * @param dirs
   */
  public static void deleteDirectories(File...dirs) {
    for (File dir : dirs) {
      deleteDirectory(dir);
    }
  }
  
  private static void deleteDirectory(File dir) {
    if (!dir.exists()) return;
    assert dir.isDirectory();
    for (File file : dir.listFiles()) {
      if (file.isDirectory()) {
        deleteDirectory(file);
      } else {
        file.delete();
      }
    }
    dir.delete();
  }

  /**
   * Find and kill processes running the indicated program as this user
   * @param string grep argument for finding the process
   */
  public static void killProcessesRunning(String string) {
    // ps command to find processes of this user
    String[] psCmd = {
        "ps",
        "aw"
    };
    String psOutput = Util.exec(psCmd, "ps aw", true, null, null);
    String[] lines = psOutput.split("\n");
    for (String line : lines) {
      if (line.contains(string)) {
        if (line.contains("grep")) continue;
        String pid = line.trim().split(" +")[0];
        String[] killCmd = {
            "kill",
            pid
        };
        exec(killCmd, "kill " + pid, true, RPKI_ROOT, null);
      }
    }
  }

  /**
   * Initialize the database
   */
  public static void initDB() {
    String[] cmd = {
        "run_scripts/initDB.sh"
    };
    exec(cmd, "initDB", true, RPKI_ROOT, null);
  }
}
