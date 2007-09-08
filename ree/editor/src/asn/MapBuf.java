/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE—RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

// char sfcsid[] = "@(#)MapBuf.java 622E"

/**
 * Title:        <p>
 * Description:  <p>
 * Copyright:    Copyright (c) <p>
 * Company:      <p>
 * @author
 * @version 1.0
 */
package asn;

public class MapBuf
{
  private int[] buf;
  private int ptr;
  private int lth;

  public MapBuf()
  {
    buf = null;
    ptr = 0;
    lth = 0;
  }

  public MapBuf(int size)
  {
    buf = new int[size];
    lth = size;
    ptr = 0;
  }

  public void set(int val, int index)
  {
    buf[index] = val;
  }

  public void set(int val)
  {
    buf[ptr] = val;
  }

  public int get(int index)
  {
    return buf[index];
  }

  public int get()
  {
    return buf[ptr];
  }

  public void incrPtr()
  {
    ptr++;
  }

  public void incrPtr(int num)
  {
    ptr += num;
  }

  public void incrVal(int index)
  {
    buf[index]++;
  }


  public void incrVal()
  {
    buf[ptr]++;
  }

  public int getPtr()
  {
    return ptr;
  }

}
