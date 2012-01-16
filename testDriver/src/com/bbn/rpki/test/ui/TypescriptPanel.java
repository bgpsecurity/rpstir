/*
 * Created on Dec 13, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.io.FilterReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingConstants;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;

import com.bbn.rpki.test.objects.TypescriptLogger;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class TypescriptPanel implements TypescriptLogger {
  /**
   * Specify how scrolling should occur. Options are ON, OFF, and AUTO. If OFF,
   * no scrolling ever occurs. If ON, scrolling always occurs. If AUTO,
   * scrolling occurs if the cursor is positioned at the end of the buffer.
   *
   * @author tomlinso
   */
  public enum ScrollLock {
    /** Scroll if cursor at end of buffer */
    AUTO,
    /** Always scroll */
    ON,
    /** Never scroll */
    OFF
  }
  private static StyleContext styleContext = new StyleContext();
  static {
    Style basicStyle = styleContext.addStyle("basic", null);
    StyleConstants.setFontFamily(basicStyle, "Monospaced");
    StyleConstants.setFontSize(basicStyle, 10);
    Style stderrStyle = styleContext.addStyle("stderr", basicStyle);
    StyleConstants.setForeground(stderrStyle, Color.RED);
    Style stdoutStyle = styleContext.addStyle("stdout", basicStyle);
    StyleConstants.setForeground(stdoutStyle, Color.BLACK);
    StyleConstants.setFontFamily(stdoutStyle, "Monospaced");
    StyleConstants.setFontFamily(stderrStyle, "Monospaced");
  }

  private final StyledDocument styledDocument = new DefaultStyledDocument(styleContext);
  private final JTextPane textPane = new JTextPane(styledDocument);
  private final JScrollPane scrollPane = new JScrollPane(textPane);
  private final JPanel panel = new JPanel(new BorderLayout());
  private ScrollLock scrollLock = ScrollLock.OFF;

  /**
   * @return the scrollLock
   */
  public ScrollLock getScrollLock() {
    return scrollLock;
  }

  /**
   * @param scrollLock the scrollLock to set
   */
  public void setScrollLock(ScrollLock scrollLock) {
    this.scrollLock = scrollLock;
  }

  /**
   * @return the component
   */
  public Component getComponent() {
    return panel;
  }

  /**
   * @param title display at the top of the panel
   */
  public TypescriptPanel(String title) {
    textPane.setEditable(false);
    scrollPane.setPreferredSize(new Dimension(800, 300));
    panel.add(scrollPane);
    JLabel titleLabel = new JLabel(title);
    titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
    panel.add(titleLabel, BorderLayout.NORTH);
  }

  /**
   * Add a source of text for this typescript.
   * The text will read until EOF is reached and appended to the document in
   * the specified style. The cursor is advanced to the new end of the document
   * and the text scrolled so the cursor is visible if scroll lock is off or if
   * scroll lock is automatic and the cursor was at the end of the document.
   * @param reader
   * @param styleName
   * @return the FilterReader version of reader
   */
  @Override
  public Reader addSource(final Reader reader, final String styleName) {
    return new FilterReader(reader) {

      /**
       * @see java.io.FilterInputStream#read()
       */
      @Override
      public int read() throws IOException {
        int b = super.read();
        if (b > 0) {
          char[] bf = {(char) b};
          processChars(bf, 0, 1, styleName);
        }
        return b;
      }

      /**
       * @see java.io.FilterInputStream#read(byte[], int, int)
       */
      @Override
      public int read(char[] b, int off, int len) throws IOException {
        int ret = super.read(b, off, len);
        if (ret > 0) {
          processChars(b, off, ret, styleName);
        }
        return ret;
      }

      /**
       * @see java.io.FilterInputStream#read(byte[])
       */
      @Override
      public int read(char[] b) throws IOException {
        return read(b, 0, b.length);
      }
    };
  }

  private void processChars(char[] b, int off, int len, String styleName) {
    String s = new String(b, off, len);
    processString(s, styleName);
  }

  /**
   * @param styleName
   * @param s
   */
  private synchronized void processString(String s, String styleName) {
    int end = styledDocument.getLength();
    int caret = textPane.getCaretPosition();
    boolean doScroll = false;
    switch (scrollLock) {
    case ON:
      doScroll = false;
      break;
    case OFF:
      doScroll = true;
      break;
    case AUTO:
      doScroll = caret == end;
      break;
    }
    Style style = styleContext.getStyle(styleName);
    try {
      styledDocument.insertString(end, s, style);
    } catch (BadLocationException e) {
      e.printStackTrace();
    }
    if (doScroll) {
      textPane.setCaretPosition(styledDocument.getLength());
    }
  }

  /**
   * @see com.bbn.rpki.test.objects.TypescriptLogger#log(java.lang.String, java.lang.Object...)
   */
  @Override
  public void log(String style, Object...msg) {
    StringBuilder sb = new StringBuilder();
    for (Object o : msg) {
      sb.append(o);
    }
    processString(sb.toString(), style);
  }

  /**
   * @see com.bbn.rpki.test.objects.TypescriptLogger#log(java.lang.Object...)
   */
  @Override
  public void log(Object...msg) {
    log("stdout", msg);
  }

  /**
   * @see com.bbn.rpki.test.objects.TypescriptLogger#suckOn(java.io.InputStreamReader, java.lang.String)
   */
  @Override
  public void suckOn(final InputStreamReader inputStreamReader, final String styleName) {
    Thread t = new Thread("SuckOn " + styleName) {
      @Override
      public void run() {
        char[] bf = new char[1000];
        int nc;
        try {
          while ((nc = inputStreamReader.read(bf)) > 0) {
            processChars(bf, 0, nc, styleName);
          }
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    };
    t.start();
  }
}
