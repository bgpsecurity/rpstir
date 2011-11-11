/*
 * Created on Nov 1, 2011
 */
package com.bbn.rpki.test.ui;

import java.awt.Font;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class TextFileViewer {
  private final JTextArea viewer = new JTextArea();
  private final JScrollPane pane = new JScrollPane(viewer);
  /**
   * @param file
   * @throws IOException 
   */
  public TextFileViewer(File file) throws IOException {
    FileReader reader = new FileReader(file);
    char[] chars = new char[10000];
    int nc;
    while ((nc = reader.read(chars)) > 0) {
      viewer.append(new String(chars, 0, nc));
    }
    viewer.setEditable(false);
    viewer.setFont(new Font("Monospaced", Font.PLAIN, 12));
    JFrame frame = new JFrame(file.getName());
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    frame.add(pane);
    frame.pack();
    frame.setVisible(true);
  }

}
