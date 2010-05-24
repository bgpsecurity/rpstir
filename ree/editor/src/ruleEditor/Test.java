/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Marla Shepard, Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */


public class Test {

  public Test() {

    double s = .4 * 30 + .3 *(60 + 10+60+5) + .15 * (30+50+60+70+10) + .8*5 +
      .5 *(35+15) + .3 * (40+10) + .2 * 70 + .1 *(60+50) + 18;

    System.out.println(" Sum : " + s);
     s = .4 * 20 + .3 *(40 + 5+50+0) + .15 * (20+40+50+60+5) +
      .5 *(15+15) + .3 * (40+0) + .2 * 30 + .1 *(40+50) ;

    System.out.println(" Sum : " + s);
  }

    /*String str = "2001:0:2:3::1";

    int i, num = -1;
    int start = 0, end = 0;
    boolean stop = false;

    String[] number;
    String[] tmp = new String[8];

    System.out.println(" str: " + str);
    while (!stop) {
      end = str.indexOf(":", start);
      if (end < 0) {
	stop = true;
	end = str.length();
      }
      tmp[++num] = str.substring(start, end).trim();
      System.out.println("v6  number("+ num + "): " + tmp[num]); 
      start = end + 1;
    }
  }
     
      String X = "ffff";
      String Y = "0";
      String Z = "2";
      int x, y, z;
      int tmp;
      x = Integer.parseInt(X, 16);
      y = Integer.parseInt(Y, 16);
      z = Integer.parseInt(Z, 16);

      System.out.println(x + " " + Integer.toHexString(x & 0xFFFF));
      System.out.println(y + " " + Integer.toHexString(y & 0xFFFF));
      System.out.println(z + " " + Integer.toHexString(z & 0xFFFF));

      
      int x = 0x8000;
      int y = 0x0800;
      int z = 0x0080;

      byte[] tmp;;

      tmp = new byte[2];
      tmp[1] = (byte)(x & 0xFF);
      tmp[0] = (byte)((x >> 8) & 0xFF);
      System.out.println(" x: " + x + " -> byte: " + tmp[0] + " " + tmp[1]);
      tmp[1] = (byte)(y & 0xFF);
      tmp[0] = (byte)((y >> 8) & 0xFF);
      System.out.println(" x: " + x + " -> byte: " + tmp[0] + " " + tmp[1]);
      tmp[1] = (byte)(z & 0xFF);
      tmp[0] = (byte)((z >> 8) & 0xFF);
      System.out.println(" x: " + x + " -> byte: " + tmp[0] + " " + tmp[1]);
      */

  public static void main(String[] args) {
    new Test(); 
  }

}
