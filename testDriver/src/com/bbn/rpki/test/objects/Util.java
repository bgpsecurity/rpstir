/*
 * Created on Nov 7, 2011
 */
package com.bbn.rpki.test.objects;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.Writer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.bbn.rpki.test.util.Sucker;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class Util implements Constants {
  private static Runtime runtime = Runtime.getRuntime();

  private static PrintWriter commandLog;
  static {
    try {
      commandLog = new PrintWriter(new FileWriter("command.log"));
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private static final String B64_ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  private static DateFormat dateFormat1 = new SimpleDateFormat("yyMMddHHmmss'Z'");

  private static DateFormat dateFormat2 = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

  /**
   * The value of the RPKI_ROOT environment variable
   */
  public static File RPKI_ROOT;

  private static TypescriptLogger typescriptLogger = null;

  /**
   * @return the typescriptLogger
   */
  public static TypescriptLogger getTypescriptLogger() {
    return typescriptLogger;
  }

  /**
   * @param typescriptLogger the typescriptLogger to set
   */
  public static void setTypescriptLogger(TypescriptLogger typescriptLogger) {
    Util.typescriptLogger = typescriptLogger;
  }

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

  private static StringBuilder appendList(StringBuilder sb, String member, Iterable<?> words, boolean bracketed) {
    sb.append(member).append("=");
    if (bracketed) {
      sb.append("[");
    }
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
    if (bracketed) {
      sb.append("]");
    }
    sb.append(String.format("%n"));
    return sb;
  }

  /**
   * @param ca_obj
   */
  public static void writeConfig(CA_Obj ca_obj) {
    try {
      // No longer uses introspection.
      // Each CA_Obj supplies a Map of variables versus value.
      File configDir = new File(Constants.CONFIG_PATH);
      if (!configDir.isDirectory()) {
        configDir.mkdirs();
      }
      File outputFile = new File(ca_obj.outputfilename);
      String name = outputFile.getName();
      String cfgName = Constants.CONFIG_PATH + name + ".cfg";
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

      Map<String, Object> fieldMap = new TreeMap<String, Object>();
      ca_obj.getFieldMap(fieldMap);
      for (Map.Entry<String, Object> entry : fieldMap.entrySet()) {
        Object val = entry.getValue();
        if (val != null) {
          String member = entry.getKey();
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
              appendList(sb, member, rangeList, false);
            }
          } else if (member.equals("ipv4") || member.equals("ipv6")) {
            IPRangeList range = (IPRangeList) val;
            if (IPRangeList.isInherit(range)) {
              sb.append(String.format("%s=%s%n", member, "inherit"));
            } else {
              appendList(sb, member, range, false);
            }
          } else if (member.equals("roaipv4") || member.equals("roaipv6")) {
            IPRangeList rangeList = (IPRangeList) val;
            appendList(sb, member, rangeList, false);
          } else if (member.equals("notBefore") || member.equals("notAfter")) {
            appendDateTime(sb, member, (Calendar) val, true);
          } else if (member.equals("thisupdate") || member.equals("nextupdate")) {
            Calendar cal = (Calendar) val;
            appendDateTime(sb, member, cal, !(ca_obj instanceof Manifest));
          } else if (member.equals("fileList")) {
            @SuppressWarnings("unchecked")
            List<?> list = (List<Object>) val;
            appendList(sb, member, list, false);
          } else if (member.equals("revokedcertlist")) {
            @SuppressWarnings("unchecked")
            List<?> list = (List<Object>) val;
            appendList(sb, member, list, true);
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
   */
  public static void create_binary(CA_Obj ca_obj) {
    String[] xargs = ca_obj.xargs;
    String[] path = ca_obj.outputfilename.split("/");
    String file = path[path.length - 1];
    String[] cmdArray = new String[3 + xargs.length];
    cmdArray[0] = Constants.BIN_DIR + "/create_object";
    cmdArray[1] = "-f";
    cmdArray[2] = Constants.CONFIG_PATH + file + ".cfg";
    System.arraycopy(xargs, 0, cmdArray, 3, xargs.length);
    exec("create_object", false, false, null, null, null, cmdArray);
  }

  /**
   * @param fileName
   * @return
   */
  static String generate_ski(String fileName) {
    return exec("gen_hash", true, false, null,
                null,
                null,
                Constants.BIN_DIR + "/gen_hash", "-f", fileName);
  }

  /**
   * @param title
   * @param ignoreStatus
   * @param cwd
   * @param input
   * @param cleanCommand TODO
   * @param cmds
   * @return stdout string
   */
  public static String exec(String title, boolean ignoreStatus, File cwd, String input, String cleanCommand, List<String> cmds) {
    return exec(title, ignoreStatus, false, cwd, input, cleanCommand, cmds.toArray(new String[cmds.size()]));
  }

  /**
   * @param title
   * @param ignoreStatus TODO
   * @param showStdOut TODO
   * @param cwd
   * @param input TODO
   * @param cleanCommand TODO
   * @param cmdArray
   * @return stdout string
   */
  public static String exec(String title, boolean ignoreStatus, boolean showStdOut, File cwd, String input, String cleanCommand, String... cmdArray) {
    int status;
    try {
      if (cwd == null) {
        cwd = new File(System.getProperty("user.dir")).getAbsoluteFile();
      }
      final Process f = runtime.exec(cmdArray, null, cwd);
      Reader stdoutReader = new InputStreamReader(f.getInputStream());
      Reader stderrReader = new InputStreamReader(f.getErrorStream());
      if (showStdOut && typescriptLogger != null) {
        stdoutReader = typescriptLogger.addSource(stdoutReader, "stdout");
        stderrReader = typescriptLogger.addSource(stderrReader, "stderr");
      }
      Sucker stdout = new Sucker(stdoutReader, "stdout");
      Sucker stderr = new Sucker(stderrReader, "stderr");
      if (input != null) {
        OutputStream os = f.getOutputStream();
        Writer writer = new OutputStreamWriter(os);
        writer.write(input);
        writer.close();
      }
      status = f.waitFor();
      if (cleanCommand != null) {
        Util.killProcessesRunning(cleanCommand);
      }
      stdout.join();
      stderr.join();
      String string = stdout.getString();
      @SuppressWarnings("unused") // For debugging
      String errString = stderr.getString();
      if (DEBUG_ON && typescriptLogger != null) {
        typescriptLogger.log(cmdArray, System.getProperty("line.separator", "\n"));
        //        typescriptLogger.log(string, System.getProperty("line.separator", "\n"));
      }
      commandLog.println(Arrays.asList(cmdArray));
      commandLog.flush();
      if (status != 0) {
        String msg = String.format("%s %s status = %d%n", title, ignoreStatus ? "ignored" : "failed", status);
        if (DEBUG_ON && typescriptLogger != null) {
          typescriptLogger.log(ignoreStatus ? "stdout" : "stderr", msg);
          if (!ignoreStatus) {
            typescriptLogger.log(errString);
            throw new RuntimeException(msg);
          }
        }
      }
      return string;
    } catch (Exception e) {
      if (e instanceof RuntimeException) {
        throw (RuntimeException) e;
      }
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
      return exec("gen_hash", true, false, null, null, null, cmdArray);
    }
  }

  /**
   * @param string
   * @param prefix
   * @return the supplied string with the given prefix removed
   */
  public static String removePrefix(String string, String prefix) {
    // TODO figure out why string sometimes starts with s: whereas prefix starts with r:
    //    assert string.startsWith(prefix);
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
    if (!dir.exists()) {
      return;
    }
    assert dir.isDirectory();
    for (File file : dir.listFiles()) {
      if (file.isDirectory()) {
        deleteDirectory(file);
      } else {
        boolean success = file.delete();
        assert success;
      }
    }
    boolean success = dir.delete();
    assert success;
  }

  /**
   * Find and kill processes running the indicated program as this user
   * @param string grep argument for finding the process
   */
  public static void killProcessesRunning(String string) {
    // ps command to find processes of this user
    String psOutput = Util.exec("ps -aef", true, false, null, null, null, "ps", "-aef");
    String[] lines = psOutput.split("\n");
    List<String> cmd = new ArrayList<String>();
    cmd.add("kill");
    for (String line : lines) {
      if (line.contains(string)) {
        if (line.contains("grep")) {
          continue;
        }
        String pid = line.trim().split(" +")[1];
        cmd.add(pid);
      }
    }
    if (cmd.size() > 1) {
      exec("Kill", true, RPKI_ROOT, null, null, cmd);
    }
  }

  /**
   * Initialize the database
   */
  public static void initDB() {
    File repositoryDir = new File(RPKI_ROOT, "REPOSITORY");
    repositoryDir.mkdirs();
    new File(RPKI_ROOT, "LOGS").mkdirs();
    exec("initDB", true, false, RPKI_ROOT, null, null,  "proto/rcli", "-x", "-t", repositoryDir.getPath(), "-y");
  }
}
