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
package extensions;
import java.util.ArrayList;
import java.math.BigInteger;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class IPAddrBlocks extends AsnSequenceOf
    {
    static final int NBUFS = 4;
    static final int MYBUF = 20;
    static int max_lth;
    public IPAddressFamily iPAddressFamily = new IPAddressFamily();
    public IPAddrBlocks()
        {
        _setup((AsnObj)null, iPAddressFamily, (short)0, (int)0x0);
        }
    public IPAddrBlocks set(IPAddrBlocks frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    private ArrayList v4ErrList = new ArrayList(0);
    private ArrayList v6ErrList = new ArrayList(0);

    public Integer[] get_v4ErrList()
        {
        Integer[] tmp = new Integer[v4ErrList.size()];
        tmp = (Integer[])v4ErrList.toArray(tmp);
        return tmp;
        }

    public Integer[] get_v6ErrList()
        {
        Integer[] tmp = new Integer[v6ErrList.size()];
        tmp = (Integer[])v6ErrList.toArray(tmp);
        return tmp;
        }

    public int checkIPAddr() 
        {
        int[] buf0 = new int[MYBUF];
        int[] buf1 = new int[MYBUF];
        int[] buf2 = new int[MYBUF];
        int[] buf3 = new int[MYBUF];
        v4ErrList = new ArrayList(0);
        v6ErrList = new ArrayList(0);
        AsnByteArray dumbuf = new AsnByteArray();
        int ansr, i, j, k, l, m, n, x, nbufs; 
        IPAddressOrRange ipAddrOrRangep = new IPAddressOrRange();
    
        for (l = 0, n = numitems(); l < n; l++)
            {
            IPAddressFamily ipAddrFam = (IPAddressFamily)iPAddressFamily.index(l);
            convert2IntArray(buf0, dumbuf); 
            if (buf0[1] == 1) max_lth = 5;
            else max_lth = 17;
            IPAddressChoice ipAddressChoice = ipAddrFam.ipAddressChoice;
            AddressesOrRangesInIPAddressChoice addressesOrRanges = 
                ipAddressChoice.addressesOrRanges;
            ArrayList locErrList = (l == 0)? v4ErrList: v6ErrList; 
            if (addressesOrRanges.size() > 0)
                {
                for (k = 0; k < MYBUF; k++)
                    {
                    buf0[k] = 0;
                    buf1[k] = 0;
                    buf2[k] = 0;
                    buf3[k] = 0;
                    }
                x = 0;
                IPAddressOrRange ipAddrOrRange = 
                    addressesOrRanges.iPAddressOrRange.index(0);
                if (fill_bufs(ipAddrOrRange, buf0, buf1) < 0) 
                    note_error(0, locErrList);
                k = nbufs = 1;
                for (m = addressesOrRanges.numitems(); k < m || nbufs > 0; k++)
                    {
                    /*
                    Low has lower in buf0, higher in buf1
                    High has "     " buf2,   "     " buf3

                    */
                    while (k < m && nbufs < 2)
                        {
                        ipAddrOrRange = addressesOrRanges.iPAddressOrRange.index(k);
                        if (fill_bufs(ipAddrOrRange, buf2, buf3) < 0) 
                            note_error(k, locErrList); 
                        nbufs++;
                        }
                    // System.out.println("k " + k);
                    if (nbufs > 1)
                        {
                        if ((buf1[0] > 0 &&   // low is range
                            range_lap(buf1, buf2) > 0) ||
                            (buf1[0] == 0 && overlap(buf0, buf2) > 0)) // low is prefix
                             note_error(k - 1, locErrList);
                        }
                    for (int ii = 0; ii < MYBUF; ii++)
                        {
                        buf0[ii] = buf2[ii];
                        buf1[ii] = buf3[ii];
                        }                
                    nbufs--;
                    }
                }
            }
        return v4ErrList.size() + v6ErrList.size();
        }

    void add_one(int[] tbuf)
        {
        for (int n = MYBUF; --n >= 3; )
            {
            tbuf[n]++;
            if (tbuf[n] > 0xFF) tbuf[n] &= 0xFF;
            else break; // if no carry created, break
            }
        }
    
    void check_prefix(int[] buf)
        {  // zeroize bits that don't count
        byte mask;
        int i = buf[2];   // count of bits that don't count
    
        for (mask = (byte)0xFF; i-- != 0; mask <<= 1);  // e.g. buf[2]=2, mask = 0xFC 
        i = buf[1] + 1;   // index to last byte
        buf[i] &= mask;     
        }
    
    int check_range(int[] lbuf, int[] hbuf)
        {
        int i;  
        for (i = 0; i < MYBUF && lbuf[i] == hbuf[i]; i++);
        if (lbuf[i] > hbuf[i]) return 1;
        return 0;
        }

    int compare_buf(int[] lbuf, int[] hbuf)
        {
        int ansr = 0;
        for (int i = 3; i < MYBUF && ansr == 0; i++)
            {
            if (lbuf[i] < hbuf[i]) ansr = -1;
            else if (lbuf[i] > hbuf[i]) ansr =  1;
            }
        return ansr;
        }

    void convert2IntArray(int[] barr, AsnByteArray dumbuf)
        {
        for (int i = 0, j = dumbuf.getLength(); i < j; i++)
            {
            barr[i] = dumbuf.index(i);
            barr[i] &= 0xFF;
            }
        }

    void copy_buf(int[] toBuf, int[] fromBuf)
        {
        for (int i = 0; i < MYBUF; toBuf[i] = fromBuf[i], i++);
        }

    int fill_bufs(IPAddressOrRange ipAddrOrRange, int[] tlbuf, 
        int[] thbuf)
        {
        int ansr, siz;
        AsnByteArray ldumbuf = new AsnByteArray();
        for (int i = 0; i < MYBUF; i++)
            {
            tlbuf[i] = 0;
            thbuf[i] = 0;
            }
        siz = ipAddrOrRange.addressPrefix.size();
        if (siz > 0)
            {    
            if ((ansr = ipAddrOrRange.addressPrefix.encode(ldumbuf)) > 0) 
                {
                convert2IntArray(tlbuf, ldumbuf);
                check_prefix(tlbuf);
                }
            }
        else 
            {
            AsnByteArray hdumbuf = new AsnByteArray();
            if ((ansr = ipAddrOrRange.addressRange.min.encode(ldumbuf)) > 0 &&         
                (ansr = ipAddrOrRange.addressRange.max.encode(hdumbuf)) > 0)
                {
                convert2IntArray(tlbuf, ldumbuf);
                convert2IntArray(thbuf, hdumbuf);
                if (test_range(tlbuf, 0) < 0 ||
                    test_range(thbuf, 1) < 0) return -1;
                make_high(thbuf);
                }
            }
        if (ansr < 0) return -1;
        if ((siz = thbuf[1]) > max_lth) return -1;
        return 1;
        }
    
    void note_error(int num, ArrayList list)
        {
        // System.out.println("Error at " + num);
        Integer i = new Integer(num);
        if (list.contains(i) == false) list.add(i);
        }

    void make_high(int[] tbuf)
        {
       int n, x, y;
        n = tbuf[1] + 1;  // tbuf[n] is last int in tbuf string
        x = ((1 << tbuf[2]) - 1);
        tbuf[n] += x;
        tbuf[n] &= 0xFF;  // fills unused bits with 1s
        for (n++; n < MYBUF; tbuf[n++] = (int)0xFF); // pads remainder with FFs
        }     

    int overlap(int[] lbuf, int[] hbuf)
        {
           // returns -1 if incremented lbuf < hbuf -- no touch
           //         0  "     "        lbuf == hbuf -- just touches
           //          1 "     "        lbuf >  hbuf -- overlaps
        int[] tbuf = new int[MYBUF];

        if (hbuf != null)
            {
            int i;
            for (i = 3; i < MYBUF && lbuf[i] == hbuf[i]; i++);
                {
                if (lbuf[i] > hbuf[i]) return 1;
                }            
            }
        copy_buf(tbuf, lbuf);
        make_high(tbuf);
        add_one(tbuf);
        // printBuf(lbuf, "lbuf ");
        // printBuf(tbuf, "tbuf ");
        // printBuf(hbuf, "hbuf ");
        return compare_buf(tbuf, hbuf);
        }

    void printBuf(int[] buf, String name)
        {
        System.out.print(name + " ");
        for (int i = 3; i < MYBUF; System.out.print(buf[i++] + " "));
        System.out.println("");
        }

    int range_lap(int[] lbuf, int[] hbuf)
        {
        int i;
        int[] tbuf = new int[MYBUF];

        copy_buf(tbuf, lbuf);
        add_one(tbuf);
        // System.out.println("Range lap");
        // printBuf(tbuf, "tbuf ");
        // printBuf(hbuf, "hbuf ");
        return compare_buf(tbuf, hbuf);
        }

    int test_range(int[] tbuf, int val)
        {
        int i, j;
        i = tbuf[tbuf[1] + 1]; // last int
        j = (1 << tbuf[2]);    // last bit that counts
        if ((val == 0 && (i & j) == 0) ||
            (val == 1 && (i & j) > 0)) 
          {
          // System.out.println("i " + i + " j " + j);
          // printBuf(tbuf, "tbuf ");
          return -1;
          }
        return 0;
        } 
    }