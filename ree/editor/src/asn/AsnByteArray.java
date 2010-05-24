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
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

// char sfcsid[] = "@(#)AsnByteArray.java 658E"
package asn;

public class AsnByteArray
{
    private byte[] array;
    private int length;
    private int ptr;

    public AsnByteArray()
    {

        array = null;
        length = 0;
        ptr = 0;
    }

    public AsnByteArray(int lth)
    {
        array = new byte[lth];
        length = lth;
        ptr = 0;
    }

    public AsnByteArray(byte[] arr, int lth)
    {
        length = lth;
        array = arr;
        ptr = 0;
    }

    public AsnByteArray(String sb)
    {
        array = sb.getBytes();
        length = sb.length();
        ptr = 0;
    }

    public AsnByteArray(AsnByteArray sb)
    {
        length = sb.getLength();
        array = new byte[length];
        for (int i=0; i<length; i++)
        {
            array[i] = sb.getArray()[i];
        }
        ptr = sb.getPtr();
    }

    public AsnByteArray subArray (int begin)
    {
        if (begin > length )
            return null;
        int newlen = length - begin;
        byte[] temp = new byte[newlen];
        for (int count = 0; count < newlen; count++)
        {
            temp[count] = array[count+begin];
        }
        AsnByteArray tmp = new AsnByteArray(newlen);
        tmp.array = temp;
        return tmp;
    }

     public AsnByteArray subArray (int begin, int lth)
    {

        if (((begin+lth) > length) )
            return null;
        byte[] temp = new byte[lth];
        for (int count = 0; count < lth; count++)
        {
            temp[count] = array[count+begin];
        }
        AsnByteArray tmp = new AsnByteArray();
        tmp.length = lth;
        tmp.array = temp;
        return tmp;
    }

    public int replaceSubArray (int begin, byte[] arr)
    {
        if (begin > length )
            return -1;
        if (begin + arr.length > length)
            return -1;
        for (int count = begin; count < length; count++)
        {
            array[count] = arr[count-begin];
        }
        return 0;
    }


    public void append(AsnByteArray str, int lth)
    {
        byte[] temp = new byte[length];
        int i; //counter
        for (i = 0; i<length; i++)
            temp[i]=array[i];
        array = new byte[(int)length + lth];
        for (i = 0; i<length; i++)
            array[i] = temp[i];
        for (i=0; i<lth; i++)
            array[i + length] = str.index(str.getPtr()+i);
        length += lth;
    }

    public void append(AsnByteArray str)
    {
      append(str, str.getLength());
    }

    public void append(byte[] str, int lth)
    {
         byte[] temp = new byte[length];
        int i; //counter
        for (i = 0; i<length; i++)
            temp[i]=array[i];
        array = new byte[length + lth];
        for (i = 0; i<length; i++)
            array[i] = temp[i];
        for (i=0; i<lth; i++)
            array[i + length] = str[i];
        length += lth;
    }

    public byte index()
    {
        if (ptr < length)
          return array[ptr];
        else
          return 0;
    }


    public byte index(int value)
    {
        if (value < length)
            return array[value];
        else return 0;
    }

    public byte indexIncrPtr()
    {
        if (ptr < length) {
	    byte b = array[ptr];
	    ptr ++;
          return b;
	  }
        else
          return 0;
    }


   public void setByte(byte value, int index)
    {
        if (index < 0) return;
        //if index >= length, insert index - length + 1 bytes at the end - last byte set to value
        if (index >= length)
        {
            byte[] temp = new byte[index-length+1];
            temp[index-length]=value;
            append(temp, index-length+1);
        }
        else array[index] = value;
    }

    public void setByte(byte value)
    {
        setByte(value, ptr);
    }

    public void setByteIncrPtr(byte value)
    {
        setByte(value, ptr);
        incrPtr();
    }

     public void insertBytes(byte[] bytes, int lth, int index)
    {
        if (index < 0) index = 0;
        //insert the bytes before the index
        //if index >= length, append bytes
        if (index >= length)
        {
            append(bytes, lth);
        }
        else
        {
            byte[] temp = new byte[lth];
            int i; //counter
            for (i = 0; i<length; i++)
                temp[i]=array[i];
            array = new byte[length + lth];
            for (i = 0; i<index; i++)
                array[i] = temp[i];
            for (i = 0; i<length; i++)
                array[i+index] = bytes[i];
            for (i=index; i<index+length; i++)
                array[i + length] = temp[i];
            length += length;
        }
        if (index <= ptr) ptr += index;
    }

    public void insertBytes(String str, int index)
    {
        insertBytes(str.getBytes(), str.length(), index);
    }

    public boolean equals (AsnByteArray arr)
    {
        if (length != arr.getLength())
            return false;
        for (int i=0; i<length; i++)
        {
            if (array[i] != arr.index(i))
                return false;
        }
        return true;
    }

    public boolean equals (byte[] str, int len)
    {
        if (length != len)
            return false;
        for (int i=0; i<length; i++)
        {
            if (array[i] != str[i])
                return false;
        }
        return true;
    }

    public int compare (AsnByteArray arr, int size)
    {
        //return 0 if they are equal through the size sent in
        //return 1 if this is bigger
        //return -1 if input is bigger
        int i;
        int retval = 0;
        for (i=0; i<size && i<length && i<arr.getLength(); i++)
        {
            if (array[i] > arr.index(i))
            {
                retval = 1;
                break;
            }
            if (array[i] < arr.index(i))
            {
                retval = -1;
                break;
            }
        }
        if (retval == 0)
        {
            //if everything up to the length of our string is the same, but the length
            //is less than size, their string is bigger, and vice versa.
            if (i >= length) retval = -1;
            else if (i >= arr.getLength()) retval = 1;
        }
        return retval;
    }

    public int getLength()
    {
        return length;
    }

    public byte[] getArray()
    {
      return array;
      }

    public int relativeLength()
    {
        return length - ptr;
    }

    public void setArray(byte[] str, int lth)
    {
        array = new byte[lth];
        length = lth;
        for (int i=0; i<length; i++)
        {
            array[i] = str[i];
        }
        ptr = 0;
    }

    public void setArray(String str)
    {
        setArray(str.getBytes(), str.length());
    }

    public void setArray(String str, int lth)
    {
        setArray(str.getBytes(), lth);
    }

    public String toString()
    {
        return new String(array);
    }

    public int getPtr()
    {
        return ptr;
    }

    public int incrPtr()
    {
        ptr++;
        if (ptr < 0) ptr = 0;
        return ptr;
    }

    public int incrPtr(int increment)
    {
        ptr += increment;
        if (ptr < 0) ptr = 0;
        return ptr;
    }

    public int decrPtr()
    {
        return incrPtr(-1);
    }

    public int decrPtr(int decrement)
    {
        return incrPtr(-decrement);
    }

    public void resetPtr(int nPtr)
    {
        ptr = nPtr;
    }

    public void resetPtr()
    {
        ptr = 0;

    }

    public void print()
      {
      if (length == 0) return;
      System.out.println(" Byte array: ");
      for (int i = 0; i < length; i++ )
        {
	int tmp = (int)array[i];
	if ((i & 15) == 0) 
	    {
            System.out.print("at ");
    	    if (i < 10) System.out.print(" ");
    	    if (i < 100) System.out.print(" ");
	    System.out.print(i + ": ");
	    }
	if (tmp < 10) System.out.print(" ");
	if (tmp < 100) System.out.print(" ");
        System.out.print(array[i] + ",");
        if ((i & 15) == 15) System.out.println();
        }
      System.out.println();

      }
}
