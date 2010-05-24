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
package extensions;
import java.util.ArrayList;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class AsNumbersOrRangesInASIdentifierChoice extends AsnSequenceOf
    {
    static final int NBUFS = 4;
    public ASNumberOrRange aSNumberOrRange = new ASNumberOrRange();
    public AsNumbersOrRangesInASIdentifierChoice()
        {
        _setup((AsnObj)null, aSNumberOrRange, (short)0, (int)0x0);
        }
    public AsNumbersOrRangesInASIdentifierChoice set(AsNumbersOrRangesInASIdentifierChoice frobj)
        {
        ((AsnObj)this).set(frobj);
	  return this;
	  }
    private ArrayList Err_list = new ArrayList(0);

    public Integer[] get_Err_list()
        {
        Integer[] tmp = new Integer[Err_list.size()];
        tmp = (Integer[])Err_list.toArray(tmp);
        return tmp;
        }
 
    public int checkASNumber()
        {
        int k, m, x, ansr, nbufs, try01, var;
        int [] ASNums = new int[NBUFS]; 
        ASNumberOrRange asNumberOrRange = new ASNumberOrRange();
        Err_list = new ArrayList(0);
     
        if (size() > 0)
            {
            nbufs = k = x = 0;
            asNumberOrRange = (ASNumberOrRange)aSNumberOrRange.index(k++);
            fill_nums(asNumberOrRange, ASNums, 0);
            nbufs++;
            for (m = numitems(); k < m || nbufs > 0; k++)
                { 
                while (k < m && nbufs < 2)
                    {
                    asNumberOrRange = (ASNumberOrRange)aSNumberOrRange.index(k);
                    fill_nums(asNumberOrRange, ASNums, 2); 
                    nbufs++;
                    }
                if (nbufs > 1)
                    {
                    var = 0;
                    if (ASNums[1] > 0) var |= 2;
                    if (ASNums[3] > 0) var |= 1;
                    try01 = 0;
                    switch (var)
                        {
                      case 0:   // low num, high num
                        if ((try01 = try_AS(ASNums[0], ASNums[2])) >= 0) 
                           // touches
                           note_error(k);
                        break;
                      case 1:   // low num, high range
                                // if touches
                        if ((ansr = try_AS(ASNums[0], ASNums[2])) >= 0)
                            note_error(k);  
                        else try01 = -1;
                        break; 
                      case 2:    // low range high num
                        if ((try01 = try_AS(ASNums[1], ASNums[2])) >= 0)
                            note_error(k); 
                        break;
                      case 3:   // low range, high range
                        if ((ansr = try_AS(ASNums[1], ASNums[2])) >= 0)
                            note_error(k); 
                        else try01 = -1;
                        break;
                      default: 
                        System.out.println("Error in check_AS num case statement");
                        }
                    }
                ASNums[0] = ASNums[2];
                ASNums[1] = ASNums[3];
                nbufs--;                              
                }
            }
        return Err_list.size();
        }
                    
    private void fill_nums(ASNumberOrRange asNumberOrRange, int[] array, int beg)
        {
        AsnIntRef ref = new AsnIntRef();
        array[beg] = array[beg + 1] = 0;
        if (asNumberOrRange.num.size() > 0)
            {
            if (asNumberOrRange.num.read(ref) > 0) 
                {
                array[beg] = ref.val;
                return; 
                }
            }
        else 
            {
            if (asNumberOrRange.range.min.read(ref) > 0) 
                {
                array[beg] = ref.val;         
                if (asNumberOrRange.range.max.read(ref) > 0) 
                    {
                    array[beg + 1] = ref.val;
                    return;
                    }
                }
            }
        System.out.println("Error encoding AS number");
        }    
    
    private void note_error(int num)
        {
        Integer i = new Integer(num);
        Err_list.add(i); 
        }
     
    private int try_AS(int lo, int hi)
        {
        if (lo > hi) return 1;
        lo++;
        if (lo > hi) return 1;
        if (lo == hi) return 0;
        return -1;
        }        
    }
