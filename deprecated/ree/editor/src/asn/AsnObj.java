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

// char sfcsid[] = "@(#)AsnObj.java 826E"
package asn;

import java.util.*;
import asn.*;
import java.io.*;

public class AsnObj
{
    protected AsnObj _next; // Next ASN on the same level
    protected AsnObj _sub;  // element of constructed
    protected AsnObj _supra; // Parent
    protected int _tag;     // context of
    protected short _type;   // Type of ASN obj, such as integer, ...
    protected short _flags;  // internal processing ASN flag, defined in AsnStatic
    protected int _min;     // Minimum allowed size of the field, could be member size
    protected int _max;     // Maximum allowed size of the field, could be member size
    protected AsnByteArray _valp;  // Data
    public AsnErrorMap error;
    static int asn_constraint_ptr = 0;
    static AsnObj recursion = null;

    public AsnObj()
    {
        _tag = 0;
        _next = null;
        _sub = null;
        _supra = null;
        _valp = null;
        _flags = 0;
        _type = 0;
        _min = 0;
        _max = 0;
        error = AsnErrorMap.instance();
    }


    public void clear()
    {
        _clear(0);
        error.asn_map_string = "";
    }

    public void asn_error(int error, String message)
    {
        System.err.println("Error #" + error + ": " + message);
    }

    public int asn_obj_err(int errorNum)
    {
	asn_error(errorNum, AsnStatic.getErrorMsg(errorNum));
        error.setErrorPtr(this);
        error.setErrorNo(errorNum);
        return -1;
    }

    protected AsnObj _dup()
    {
        AsnObj retObj = new AsnObj();
        retObj = _set_pointers(retObj);
        return retObj;
    }

    public int constraint()
    {
        //was virtual in C++ - this is all it did
        return 1;
    }

    public int copy(AsnObj asnObj)
    {
        //copy from this to asnObj
        int ansr, size;
        AsnObj sup;
        _clear_error();

        if (asnObj==null)
            return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        for (sup = asnObj; sup!=null; sup=sup._supra)
        {
            if ((sup._supra!=null) && ((sup._supra._flags & AsnStatic.ASN_OF_FLAG)!=0)
                && (sup._next==null))
                return asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
        }
        if (_type == AsnStatic.ASN_BITSTRING)
            size = ((AsnBitString)this).vsize();
        else
            size = vsize();
        if (size < 0)
        {
            if (error.getErrorNo() != 0) return size;
            return asn_obj_err(AsnStatic.ASN_EMPTY_ERR);
        }
        else if (size == 0)
        {
            AsnByteArray emptyArr = new AsnByteArray(size);
            if ((_flags & AsnStatic.ASN_FILLED_FLAG)!=0)
                ansr = asnObj.write(emptyArr, 0);
            else ansr=0;
        }
        else
        {
            AsnByteArray array = new AsnByteArray(size);
            if (_type == AsnStatic.ASN_BITSTRING)
                {
                AsnIntRef shift = new AsnIntRef();
                if ((ansr = ((AsnBitString)this).read(array,shift)) > 0)
                    ansr = ((AsnBitString)asnObj).write(array, size, shift.val);
                }
            else
            {
                ansr = read(array);
                if (ansr>0)
                    ansr = asnObj.write(array,size);
            }
        }
        return ansr;
    }

    public int decode(AsnByteArray buf)
    {
        int lth = _find_lth(buf);
        if (lth < 0) return lth;
        return decode(buf, lth);
    }

    public int decode(AsnByteArray buf, int lth)
        {
        int[] map_buf = new int[20];
	int map_index = 0;
        int holder = buf.getPtr();
        AsnObj obj = this;
        AsnObj tobj;
        int ansr;
	AsnObjRef objref = new AsnObjRef();
        _clear_error();
        if (buf == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        map_buf[0] = 0;
        map_buf[1] = -1;
        clear();
        if ((buf.index(holder) == 0) && (buf.index(holder+1) == 0)) return 0;
        if ((_flags & AsnStatic.ASN_DEFINED_FLAG) != 0)
            {
            for (obj = obj._sub; (obj!=null) && ((obj._flags & AsnStatic.ASN_CHOSEN_FLAG)==0);
                obj = obj._next);
            if (obj == null)
                return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
            }
	objref.obj = this;
        tobj = _tag_scan(objref, buf,((_supra != null) ?
            (_supra._flags & AsnStatic.ASN_OF_FLAG) : 0), map_buf, 0);
        if (tobj == null)
        {
            buf_stuff(map_buf);
            return asn_obj_err(AsnStatic.ASN_MATCH_ERR);
        }
        ansr = tobj._match(buf, (buf.getPtr()+lth));
        if ((ansr >= 0) && (error.getConstraintPtr() != null))
        {
            ansr = (buf.getPtr() - error.getConstraintPtr().intValue());
            size();
        }
        return ansr;
    }

    public int diff(AsnObj asnObj)
    {
        int size, tosize;
        if (asnObj == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        if ( ((_flags & AsnStatic.ASN_FILLED_FLAG)==0) ||
            ((asnObj._flags & AsnStatic.ASN_FILLED_FLAG)==0) )
            return -1;
        if ((_type == AsnStatic.ASN_UTCTIME) || (_type == AsnStatic.ASN_GENTIME))
        {
            if ((asnObj._type != AsnStatic.ASN_UTCTIME)
                && (asnObj._type != AsnStatic.ASN_GENTIME))
                return -1;
            AsnIntRef bb = new AsnIntRef(0),
                cc = new AsnIntRef(0);
            if ((read(bb) < 0) || (asnObj.read(cc) < 0)) return -1;
            if (bb.val == cc.val) size = 0;
            else size = 1;
        }
        else
        {
            AsnByteArray buffer1 = new AsnByteArray();
            AsnByteArray buffer2 = new AsnByteArray();
            if ( ((size = vsize())<0) || ((tosize = asnObj.vsize())<0) )
                return asn_obj_err(AsnStatic.ASN_MEM_ERR);
            if (size != tosize) size = -1;
            else if ( (re_read(buffer1)<0) || (asnObj.re_read(buffer2)) < 0) size = -1;
            else if ((buffer1.compare(buffer2, (int)size))<0) size = 1;
        }
        return 0;
    }

    public int dump(AsnByteArray to)
    {
        _clear_error();
        int ansr = _dumpsize(to, 0, AsnStatic.ASN_RE_READING);
        if (ansr >= 0) ansr++;
        return ansr;
    }

    public int dump_size()
    {
        AsnByteArray to = new AsnByteArray();
        _clear_error();
        int ansr = _dumpsize(to, 0, AsnStatic.ASN_RE_SIZING);
        if (ansr >= 0) ansr++;
        return ansr;
    }

    public int encode(AsnByteArray to)
        {
        _clear_error();
	int lth = _encodesize(to, 1);
	to.resetPtr();
	return lth;
        }

    public int get_file(String filename)
    {
        int ansr;
        int ovfl = 0;
        ansr = get_file(filename, ovfl);
        if ((ansr > 0) && (ovfl != 0))
        {
            asn_obj_err(AsnStatic.ASN_FILE_ERR);
            ansr=-ansr;
        }
        return ansr;
    }

    public int get_file(File file)
    {
        int ansr;
        int ovfl = 0;
        ansr = get_file(file, ovfl);
        if ((ansr > 0) && (ovfl != 0))
        {
            asn_obj_err(AsnStatic.ASN_FILE_ERR);
            ansr=-ansr;
        }
        return ansr;
    }

    public int get_file(String filename, int overflow)
    {
        File inFile = new File(filename);
        return (get_file(inFile, overflow));
    }

    public int get_file(File file, int overflow)
    {
        int size, lth;
        AsnByteArray input = new AsnByteArray();
        FileInputStream stream;

        try
        {
            if (!file.exists()) return -1;
            stream = new FileInputStream(file);
            int temp;
            byte bytes[] = new byte[256];
            while ((temp = stream.read(bytes)) != -1)
            {
                input.append(bytes, temp);
            }
            stream.close();

        }
        catch (Exception e)
        {
            e.printStackTrace();
            return -1;
        }
        size = input.getLength();
        lth = decode(input);
        if (lth != size)
        {
            if (lth > 0) overflow = size - lth;
            size = lth;
        }
        return size;
    }

    public int _get_sub_tag()
    {
        return _tag;
    }

    public int put_file(String filename)
    {
        File outFile = new File(filename);
              return (put_file(outFile));
    }

    public int put_file(File file)
    {
        int ansr;
        FileOutputStream stream;
        ansr = size();
        if (ansr < 0) return ansr;
        AsnByteArray output = new AsnByteArray(ansr);
        if (encode(output) != ansr) return -1;
        try
        {
            stream = new FileOutputStream(file);
            for (int temp = 0; temp < ansr; temp++)
            {
                byte b = output.index(temp);
                stream.write(b);
            }

            stream.close();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return -1;
        }
        return ansr;
    }

    public int read(AsnByteArray to)
    {
        AsnIntRef shift = new AsnIntRef();
        AsnObj obj = _check_choice();
        if (obj == null)
        {
            if ((_type == AsnStatic.ASN_CHOICE) && ((_flags &
                AsnStatic.ASN_DEFINED_FLAG)!=0) && (_tag < AsnStatic.ASN_APPL_SPEC) &&
                (_tag != AsnStatic.ASN_BOOLEAN))
                return asn_obj_err(AsnStatic.ASN_DEFINED_ERR);
            return ((_flags & AsnStatic.ASN_OPTIONAL_FLAG) == 0) ? -1 : 0;
        }
        if (obj.getClass().toString() == "asn.AsnObjectIdentifier")
            return ((AsnObjectIdentifier)obj)._readsize(to, AsnStatic.ASN_READING);
        if (obj.getClass().toString() == "asn.AsnOIDTableObj")
            return ((AsnOIDTableObj)obj)._readsize(to, AsnStatic.ASN_READING);
        if (obj._type == AsnStatic.ASN_BITSTRING)
            return ((AsnBitString)obj).read(to, shift);
        if ((_flags & AsnStatic.ASN_ENUM_FLAG)!=0)
            return _enum_readsize(to, AsnStatic.ASN_READING);
        if ((_type == AsnStatic.ASN_CHOICE) && ((_flags &
            AsnStatic.ASN_DEFINED_FLAG)!=0) && (_tag < AsnStatic.ASN_APPL_SPEC) &&
            (_tag != AsnStatic.ASN_BOOLEAN))
        {
            if (obj._type != AsnStatic.ASN_NOTASN1)
                return obj._encodesize(to,AsnStatic.ASN_READING);
        }
        return _readsize(to, AsnStatic.ASN_READING);
    }

    public int read(AsnIntRef to)
        {
        AsnObj obj;
        int i;
        int size = 0;
        int ansr, temp;
        AsnByteArray buf = new AsnByteArray();
        final int INT_SIZE=4;
        if (to == null)
            return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        if ((_flags & AsnStatic.ASN_ENUM_FLAG) != 0)
            {
            size = _enum_readsize(buf, AsnStatic.ASN_READING);
            if (size <= 0) return size;
            for (i = 0, to. val = 0; size-- != 0;
                to.val = (to.val << 8) + (((int)buf.index(i++)) & 0xFF));
            return i;
            }
        if ((obj = _check_choice()) == null)
            return ((_flags & AsnStatic.ASN_OPTIONAL_FLAG)==0) ? -1 : 0;
        if ((obj._supra!=null) && ((obj._supra._flags & AsnStatic.ASN_OF_FLAG)!=0) &&
            (obj._next == null))
            return asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
        if ((obj._type != AsnStatic.ASN_BOOLEAN) && (obj._type != AsnStatic.ASN_INTEGER) &&
            (obj._type != AsnStatic.ASN_ENUMERATED) && (obj._type != AsnStatic.ASN_UTCTIME)
            && (obj._type != AsnStatic.ASN_GENTIME))
            return asn_obj_err(AsnStatic.ASN_TYPE_ERR);
        if ((obj._type == AsnStatic.ASN_UTCTIME) || (obj._type == AsnStatic.ASN_GENTIME))
            return ((AsnTime)obj).read(to);
        if (obj._valp != null && (size = obj._valp.getLength()) > INT_SIZE)
            return asn_obj_err(AsnStatic.ASN_BOUNDS_ERR);
        to.val = 0;
        if ((i = obj._check_vfilled()) <= 0)
            {
            if (i == 0 && (((obj._flags & AsnStatic.ASN_DEFAULT_FLAG) != 0) ||
                (((obj._flags & AsnStatic.ASN_CHOSEN_FLAG) != 0) && (obj._supra != null)
                && ((obj._supra._flags & AsnStatic.ASN_DEFAULT_FLAG) != 0))))
                {
                if (obj._type == AsnStatic.ASN_BOOLEAN)
                    {
                    to.val = (((AsnBoolean)obj)._default & AsnStatic.BOOL_DEFAULT);
                    i = 1;
                    }
                else if (((obj._type == AsnStatic.ASN_ENUMERATED) ||
                    (_type == AsnStatic.ASN_INTEGER)) && (obj._sub != null))
                    {
                    AsnObj sub;
                    for (sub = obj._sub; sub != null && (sub._flags &
                        AsnStatic.ASN_DEFAULT_FLAG) == 0; sub = sub._next);
                    if (sub == null) return -1;
                    i = sub.tag(to);
                    }
                else if (obj._type == AsnStatic.ASN_INTEGER)
                    {
                    to.val = ((AsnInteger)obj)._default;
                    if ((to.val == 0) || (to.val == -1)) i = 1;
                    else if (to.val < 0)
                        for (ansr = to.val; ansr != -1; i++, ansr >>= 8);
                    else
                        for (ansr = to.val; ansr != 0; i++, ansr >>= 8);
                    }
                return i;
                }
            return obj._read_empty(i, AsnStatic.ASN_READING);
            }
        if (obj._type == AsnStatic.ASN_NULL) return 0;
        if ((obj._valp.index(0) & 0x80) != 0)
          to.val = -1;
        for (i = 0; size-- != 0; to.val = (to.val << 8) +
            (((int)obj._valp.index(i++)) & 0xFF));
        return i;
        }

    public int re_encode(AsnByteArray to)
        {
        _clear_error();
        int lth =  _encodesize(to, AsnStatic.ASN_RE_READING);
	to.resetPtr();
	return lth;
        }

    public int re_read(AsnByteArray to)
    {
        AsnIntRef shift = new AsnIntRef();
        if (_type == AsnStatic.ASN_OBJ_ID)
            return ((AsnObjectIdentifier)this).read(to);
        else if (_type == AsnStatic.ASN_BITSTRING)
            return ((AsnBitString)this).read(to, shift);
        return _readsize(to, AsnStatic.ASN_RE_READING);
    }

    public int re_size()
    {
        AsnByteArray array = new AsnByteArray();
        _clear_error();
        return _encodesize(array, AsnStatic.ASN_RE_SIZING);
    }

    public int re_vsize()
    {
        AsnByteArray array = new AsnByteArray();
        return _readsize(array, AsnStatic.ASN_RE_SIZING);
    }

    public void set(AsnObj asnObj)
    {
	AsnObj tobj;
        if ((_flags & AsnStatic.ASN_FILLED_FLAG)!= 0) clear();
        if ((_type != asnObj._type) || ((_flags & AsnStatic.ASN_OF_FLAG) !=
            (asnObj._flags & AsnStatic.ASN_OF_FLAG)))
	    {
            asn_obj_err(AsnStatic.ASN_MATCH_ERR);
	    return;
	    }
        if ((asnObj._flags & AsnStatic.ASN_FILLED_FLAG)==0) return;
        if (asnObj._type == AsnStatic.ASN_CHOICE)
            ((AsnChoice)this).set((AsnChoice)asnObj);
        else if ((asnObj._flags & AsnStatic.ASN_OF_FLAG)!=0)
            ((AsnOf)this).set((AsnOf)asnObj);
        else if (asnObj._type == AsnStatic.ASN_SEQUENCE)
            ((AsnSequence)this).set((AsnSequence)asnObj);
        else if (asnObj._type == AsnStatic.ASN_SET)
            ((AsnSet)this).set((AsnSet)asnObj);
        else if (asnObj._valp == null) return;
        else if (((_flags & AsnStatic.ASN_TABLE_FLAG)!=0) || (_sub != null))
        {
            if (asnObj.copy(this) < 0) return;
        }
        else
        {
            _valp = new AsnByteArray(asnObj._valp.toString());
            _fill_upward(AsnStatic.ASN_FILLED_FLAG);
        }
    }

    public int size()
    {
        AsnByteArray to = new AsnByteArray();
        _clear_error();
        return _encodesize(to, 0);
    }

    public int tag(AsnIntRef ansr)
    {
        int tag;
        AsnObj obj;
        if (ansr == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        if ((obj = _check_choice()) == null)
            return ((_flags & AsnStatic.ASN_OPTIONAL_FLAG)==0) ? -1 : 0;
        ansr.val = 0;
        int i = 0;
        if ((obj._type != AsnStatic.ASN_CHOICE) ||
            ((obj._flags & AsnStatic.ASN_FILLED_FLAG) != 0))
        {
            for (tag = obj._tag; tag!=0; tag >>= 8, i++)
                ansr.val = (ansr.val << 8) | (tag & 0xFF);
        }
        return i;
    }

    public int vsize()
    {
        AsnByteArray str = new AsnByteArray();
        if (_type == AsnStatic.ASN_OBJ_ID)
            return ((AsnObjectIdentifier)this)._readsize(str,0);
        else if (_type == AsnStatic.ASN_BITSTRING)
            return ((AsnBitString)this).vsize();
        else if ((_flags & AsnStatic.ASN_ENUM_FLAG)!=0)
            return _enum_readsize(str,0);
        else return _readsize(str,0);
    }

    public int write(String from)
	{
	AsnByteArray ba = new AsnByteArray(from);
	return write(ba, ba.getLength());
	}

    public int write(AsnByteArray from, int lth)
        {
        AsnObj tobj = this;
        int ansr;

        _clear_error();
        if (from == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        if (((_flags & AsnStatic.ASN_DEFINED_FLAG) != 0) &&
            ((tobj = tobj._check_defined()) == null))
            return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
        if (tobj._type == AsnStatic.ASN_BITSTRING)
            ansr = ((AsnBitString)tobj).write(from, lth, 0);
        else if (tobj._type == AsnStatic.ASN_NONE)
            ansr = asn_obj_err(AsnStatic.ASN_NONE_ERR);
        else if ((tobj != this) && (_tag < AsnStatic.ASN_APPL_SPEC))
            ansr = tobj.decode(from, lth);
        else ansr = tobj._write(from, lth);
        if ((ansr >= 0) && (tobj.constraint() == 0))
            return asn_obj_err(AsnStatic.ASN_CONSTRAINT_ERR);
        return ansr;
        }

    public int write(AsnByteArray from)
    {
        return write(from, from.getLength());
    }

    public int write(int value)
    {
        AsnObj obj = this;
        AsnByteArray buf = new AsnByteArray(20);
        int iter;
        /* step 1 */
        if ((((_flags & AsnStatic.ASN_DEFINED_FLAG)!=0) &&
            ((obj = _check_defined())==null)) ||
            ((_supra!=null) && ((_supra._flags & AsnStatic.ASN_DEFINED_FLAG)!=0) &&
            ((obj = _supra._check_defined())) != this))
            return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
        if (obj==null) return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
        if ((obj._type != AsnStatic.ASN_BOOLEAN) &&
            (obj._type != AsnStatic.ASN_INTEGER) &&
            (obj._type != AsnStatic.ASN_ENUMERATED) &&
            (obj._type != AsnStatic.ASN_UTCTIME) &&
            (obj._type != AsnStatic.ASN_GENTIME) &&
            ((obj._flags & AsnStatic.ASN_ENUM_FLAG)==0))
            return asn_obj_err(AsnStatic.ASN_TYPE_ERR);
        /* step 2 */
        if (obj._type == AsnStatic.ASN_UTCTIME) return ((AsnTime)obj).write(value);
        else if (obj._type == AsnStatic.ASN_BOOLEAN)
        {
            iter = 1;
            byte temp = (value != 0)? (byte)1:(byte)0;
            buf.setByte(temp, 0);
        }
        else
        {
            int tmp = value;
            if (value<0)
                for (iter = 0; tmp != -1; tmp >>= 8, iter++)
                {
                    if (tmp < -0x80 && tmp > -0x100) iter++;
                }
            else for (iter = 0; tmp != 0; tmp >>= 8, iter++)
            {
                    if (tmp >= 0x80 && tmp < 0x100) iter++;
            }
            if (iter==0) iter++;
            tmp = value;
            for (int loc = iter-1; loc >= 0; buf.setByte((byte)(tmp & 0xFF), loc--),
                tmp >>= 8);
        }
        return (int)(obj.write(buf, iter));
    }

    public boolean equals(AsnObj asnObj)
    {
        AsnObj thisChoice = _check_choice();
        AsnObj inChoice = asnObj._check_choice();
        if ((thisChoice._type != inChoice._type) || ((thisChoice._flags &
            AsnStatic.ASN_OF_FLAG) != (inChoice._flags & AsnStatic.ASN_OF_FLAG)))
            return false;
        if (((thisChoice._flags & AsnStatic.ASN_FILLED_FLAG) !=
            (inChoice._flags & AsnStatic.ASN_FILLED_FLAG)))
            return false;
        if ((thisChoice._flags & AsnStatic.ASN_FILLED_FLAG)==0)
            return true;
        if ((thisChoice._type & AsnStatic.ASN_CONSTRUCTED)!=0)
            return (((AsnSequence)thisChoice).equals((AsnSequence)inChoice));
        if ((thisChoice._valp == null) != (inChoice._valp == null))
            return false;
        return inChoice._valp.equals(thisChoice._valp);
    }

    public boolean greaterThanOrEquals(AsnObj asnObj)
    {
        return (_compare(asnObj) >= 0);
    }

    public boolean lessThanOrEquals(AsnObj asnObj)
    {
        return (_compare(asnObj) <= 0);
    }

    public boolean greaterThan(AsnObj asnObj)
    {
        return (_compare(asnObj) > 0);
    }

    public boolean lessThan(AsnObj asnObj)
    {
        return (_compare(asnObj) < 0);
    }

    public void map()
    {
        //for now, will not be implemented in this version of the library
        //keep the function declaration here for future reference
    }
/* char_table masks are:
    numeric       1              ' ' = ia5 only,
    printable     4              '0' = ia5 & visible
    t61 (teletex) 8              '(' =  "  &t61
    visible    0x10              '8' =  " , visible & t61
    ia5        0x20              '<' =  " ,    "   ,   ", & printable
                                 '=' =  "  ,  "    ,   ",     "  & numeric
as agreed by John Lowry and Charlie Gardiner on May 23, 1996! and
corrected by CWG on May 3, 2001 */

    protected static final char mask_table[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0,
                                                0, 0, 1, 4, 8, 0, 32, 0,
                                                0, 0, 16, 0, 0, 0, 0, 0};
    protected static final char char_table[] =
    { ' ',' ',' ',' ',' ',' ',' ',' ','(',' ','(',' ','(','(','(','(',
      ' ',' ',' ',' ',' ',' ',' ',' ',' ','(','(','(',' ','(',' ',' ',
      '=','8','8','8','8','8','8','<','<','<','8','<','<','<','<','<',
      '=','=','=','=','=','=','=','=','=','=','<','0','0','<','0','<',
      '8','<','<','<','<','<','<','<','<','<','<','<','<','<','<','<',
      '<','<','<','<','<','<','<','<','<','<','<','8','0','8','0','8',
      '0','<','<','<','<','<','<','<','<','<','<','<','<','<','<','<',
      '<','<','<','<','<','<','<','<','<','<','<','0','8','0','0','0',
      ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','(','(',' ',' ',' ',
      ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','(',' ',' ',' ',' ',
      ' ','(','(','(','(','(','(','(','(',' ',' ','(',' ',' ',' ',' ',
      '(','(','(','(','(','(','(','(','(',' ',' ','(','(','(','(','(',
      ' ','(','(','(','(','(','(','(','(','(','(','(','(','(','(','(',
      ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
      '(','(','(','(','(',' ','(','(','(','(','(','(','(','(','(','(',
      '(','(','(','(','(','(','(','(','(','(','(','(','(','(','(',' ' };

    protected int _append(AsnByteArray from, int lth)
    {
        int i;
        if ((_max != 0) && (_csize(from, vsize() + lth) > _max))
            return asn_obj_err(AsnStatic.ASN_BOUNDS_ERR);
        if ((mask_table[_type] != 0) && ((i = _check_mask(from, lth)) < 0))
            return i;
        _valp.append(from, lth);
        return lth;
    }

    public void _boundset(int min, int max)
    {
        _min=min;
        _max=max;
    }


    protected AsnObj _check_choice()
        {
        AsnObj obj = this; //retval
        AsnObj tobj;       //holder
   
        while (((obj._flags & AsnStatic.ASN_POINTER_FLAG) != 0 && 
            obj._sub != null) ||
            ((obj._flags & AsnStatic.ASN_DEFINED_FLAG) != 0) ||
            ((obj._type == AsnStatic.ASN_CHOICE) &&
                ((obj._flags & AsnStatic.ASN_FILLED_FLAG) != 0)))
            {
	    if ((obj._flags & AsnStatic.ASN_POINTER_FLAG) != 0 &&
    		obj._sub != null) 
                {
                if ((obj._flags & AsnStatic.ASN_FILLED_FLAG) != 0)
                    obj = obj._sub;
                else  return null;
                }
            else if ((obj._flags & AsnStatic.ASN_DEFINED_FLAG) != 0)
                {
                for (tobj = obj._sub; (tobj != null) &&
                    ((tobj._flags & AsnStatic.ASN_CHOSEN_FLAG) == 0);
                     tobj = tobj._next);
                if (tobj == null)
                    {
                    if ((_flags & AsnStatic.ASN_OPTIONAL_FLAG) == 0)
                        asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
                    return tobj;
                    }
                if ((tobj._flags & (AsnStatic.ASN_CHOSEN_FLAG | AsnStatic.ASN_DEFINED_FLAG))
                    == (AsnStatic.ASN_CHOSEN_FLAG | AsnStatic.ASN_DEFINED_FLAG))
                        return tobj;
                obj = tobj;
                }
            else if ((obj._type == AsnStatic.ASN_CHOICE) &&
                ((obj._flags & AsnStatic.ASN_FILLED_FLAG)!=0))
                {
                for (tobj = obj._sub; (tobj!=null) &&
                    ((tobj._flags & AsnStatic.ASN_FILLED_FLAG) == 0); 
                    tobj = tobj._next);
                if (tobj == null) return obj._sub;
                obj = tobj;
                if ((obj._type == AsnStatic.ASN_CHOICE) && 
                    (obj._type != obj._tag) &&
                    ((obj._flags & AsnStatic.ASN_DEFINED_FLAG) == 0))
		    break;
                }
            }
        return obj;
        }

    protected AsnObj _check_defined()
    {
        AsnObj sub;
        for (sub = _sub; (sub!=null) && ((sub._flags & AsnStatic.ASN_CHOSEN_FLAG)==0);
            sub = sub._next);
        return sub;
    }

    protected int _check_of()
    {
        AsnObj obj;
        for (obj = this; obj!=null; obj = obj._supra)
        {
            if ((obj._supra != null) && ((obj._supra._flags & AsnStatic.ASN_OF_FLAG) != 0)
                && (obj._next == null))
                return asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
        }
        return 1;
    }

    protected int _check_efilled(int mode)
    {
        int i = _check_filled();
        if (i < -1) return 1;
        if (i > 0  && (((_flags & AsnStatic.ASN_DEFAULT_FLAG) != 0) ||
            ((_supra!=null) && (_supra._flags & (AsnStatic.ASN_DEFAULT_FLAG |
             AsnStatic.ASN_DEFINED_FLAG))== (AsnStatic.ASN_DEFAULT_FLAG |
             AsnStatic.ASN_DEFINED_FLAG))) && _is_default() > 0 &&
            ((mode & AsnStatic.ASN_RE_SIZING) == 0)) return 0;
        return i;
    }

    protected int _check_vfilled()
    {
        int i = _check_filled();
        if (i < -1) i = 0;
        return i;
    }

    protected int _check_filled()
    {
        if ((_flags & AsnStatic.ASN_FILLED_FLAG)!=0)
            return 1;
        if ((_type == AsnStatic.ASN_NONE) ||
            ((_supra != null) && ((_supra._flags & AsnStatic.ASN_OF_FLAG)!=0)
            && (_next == null)) || ((_flags & AsnStatic.ASN_OPTIONAL_FLAG)!=0)
            || (((_flags & AsnStatic.ASN_CHOSEN_FLAG)!=0) &&
            (_supra._tag != AsnStatic.ASN_CHOICE) &&
            ((_supra._flags & AsnStatic.ASN_OPTIONAL_FLAG)!=0)))
            return 0;
        if (((_flags & AsnStatic.ASN_OF_FLAG) != 0) && (_min == 0))
            return -2;
        if ((_type & AsnStatic.ASN_CONSTRUCTED) != 0 && 
            _type != AsnStatic.ASN_CHOICE)
        {
            AsnObj holder;
            for (holder = _sub; (holder!=null) &&
                ((holder._flags & AsnStatic.ASN_OPTIONAL_FLAG) != 0);
                holder = holder._next);
            if (holder == null) return -2;
        }
        return -1;
    }

    protected int _check_mask(AsnByteArray from, int lth)
    {
        char mask = mask_table[_type];
        int start = from.getPtr();
        int index;
        for (index = 0; (lth-- != 0) && ((char_table[from.index(index + start)] & mask)!=0); index++);
        //ABOVE STATEMENT NEEDS WORK - maybe OK?
        if (lth >= 0)
        {
            asn_obj_err(AsnStatic.ASN_MASK_ERR);
            // return (from - c);  WHAT SHOULD THIS BE???
            return -index; //this maybe?
        }
        return 1;
    }

    protected void _clear(int level)
        {
        AsnObj sub;

	if ((_flags & AsnStatic.ASN_POINTER_FLAG) != 0)
	    {
	    if (_sub != null && (_sub._flags & AsnStatic.ASN_DUPED_FLAG) != 0)
		_sub = null;
	    }
        if (((_tag & AsnStatic.ASN_CONSTRUCTED) != 0) ||
            ((_type == AsnStatic.ASN_CHOICE) && ((_flags &
            AsnStatic.ASN_DEFINED_FLAG) != 0)))
            {
            if (level >= 0) level++;
            if (((_flags & AsnStatic.ASN_OF_FLAG) != 0) && (_sub != null))
                {
                for (sub = _sub; sub._next != null; _sub = sub)
                    {
                    sub = sub._next;
                    _sub._next = null;
                    _sub._supra = null;
                    _sub = null;
                    }
                }
            else
                {
                for (sub = _sub; sub != null; sub = sub._next)
                    {
                    sub._clear(level);
                    }
                if (_type == AsnStatic.ASN_SET)
                    {
                    AsnSet set = (AsnSet)this;
                    set._relinksp = null;
                    }
                }
            }
        _valp = null;
        if ((_flags & AsnStatic.ASN_TABLE_FLAG) != 0)
                ((AsnTableObj)this)._set_definees(-1);
        _flags &= ~(AsnStatic.ASN_FILLED_FLAG | AsnStatic.ASN_INDEF_LTH_FLAG
                                | AsnStatic.ASN_SUB_INDEF_FLAG);

        }

    protected void _clear_error()
    {
        error.setConstraintPtr(null);
        error.setErrorNo(0);
        error.setErrorPtr(null);
        error.asn_map_string = "";
    }

    protected int _compare(AsnObj asnObj)
    {
        if ( ((_flags & AsnStatic.ASN_POINTER_FLAG)!=0) ||
            ((asnObj._flags & AsnStatic.ASN_POINTER_FLAG)!=0) ||
                (_type != asnObj._type) )
                return asn_obj_err(AsnStatic.ASN_TYPE_ERR) - 1;
        int ansr = _flags & AsnStatic.ASN_FILLED_FLAG;
        if (ansr != (asnObj._flags & AsnStatic.ASN_FILLED_FLAG))
            return ((ansr != 0) ? 1:-1);
        if (ansr == 0) return 0;
	if ((_type & AsnStatic.ASN_CONSTRUCTED) != 0)
	    {
	    int i, min, siz1 = this.vsize(), siz2 = asnObj.vsize();
	    AsnByteArray b1 = new AsnByteArray(),
		b2 = new AsnByteArray();
	    if (siz1 < siz2) min = siz1;
	    else min = siz2;
	    this.read(b1);
	    asnObj.read(b2);
	    if ((i = b1.compare(b2, min)) == 0)
		{
		if (siz1 > min) return 1;
		if (siz2 > min) return -1;
		return 0;
		}
	    return i;
	    }
        switch (_type)
            {
          case AsnStatic.ASN_BOOLEAN:
            AsnByteArray arr1, arr2;
            arr1 = new AsnByteArray();
            arr2 = new AsnByteArray();
            read(arr1);
            asnObj.read(arr2);
            byte arr1_0 = arr1.index(0);
            byte arr2_0 = arr2.index(0);
            if (arr1_0 == arr2_0) return 0;
            return ((arr1_0 < arr2_0) ? -1 : 1);

          case AsnStatic.ASN_UTCTIME:
          case AsnStatic.ASN_GENTIME:
            return ((AsnTime)this)._compare((AsnTime)asnObj);

          case AsnStatic.ASN_INTEGER:
          case AsnStatic.ASN_ENUMERATED:
            return ((AsnNumeric)this)._compare((AsnNumeric)asnObj);

          case AsnStatic.ASN_BITSTRING:
            return ((AsnBitString)this)._compare((AsnBitString)asnObj);

          case AsnStatic.ASN_NULL:
            return 0;

            default:
            break;
            }
        return ((AsnString)this)._compare((AsnString)asnObj);
    }

    protected int _compare(AsnByteArray from, int length)
    {
        int count;
        int holder = from.getPtr();
        int start = holder;
        int comp;
        if ((_valp.getLength() == 2) &&
            (_valp.index(0)==0xFF) &&
             (_valp.index(1)==0xFF))  return 0;
        if (length != _valp.getLength()) return -1;
        for (count = 0; count < length &&
            _valp.index(count) == from.index(start++); count++);
        if (count < length) return -1;
        return 0;
    }

    protected int _convertDotNotation(AsnByteArray ba, String from)
	{
        /**
        Procedure:
        1. Check characters in string
	   Get size and value of first field
	2. Find out how big remaining fields will be
	   Go to the third field
        3. Convert the dot notation to binary
	   Attach array to ba
           Return size of result
	**/
        int begin = 0, end = from.length();
        int temp, val;
        int siz;
        int count, count2;
	byte[] bytes = from.getBytes();
	byte b;
                                                         /* Step 1 */
        for (b = 0; begin < end && (((b = bytes[begin]) >= '0' && b <= '9') ||
            b == '.'); begin++);
        if (begin < end)
            return (1 - begin + asn_obj_err(AsnStatic.ASN_MASK_ERR));

        for (val = begin = 0; begin < end && (b = bytes[begin]) != '.';
            val = (val * 10) + b - '0', begin++);
        val *= 40;
        for (temp = 0, begin++; begin < end && (b = bytes[begin]) != '.';
            temp = (temp * 10) + b - '0', begin++);
        temp += val;
        for (val = temp, siz = 0; temp != 0; siz++) temp >>=7;
                                                               /* Step 2 */
        for (begin++; begin < end; begin++)
            {
            for (temp = 0; begin < end && (b = bytes[begin]) != '.';
                temp = (temp * 10) + b - '0', begin++);
            if (temp == 0) siz ++;
            else for ( ; temp != 0; siz++) temp >>= 7;
            }
        for (begin = 0; begin < end && (b = bytes[begin]) != '.'; begin++);
        for (begin++; begin < end && (b = bytes[begin]) != 0 &&
            b != '.'; begin++);
        AsnByteArray buf = new AsnByteArray(siz);

                                                          /* Step 3 */
        for (temp = val, siz = 0; temp != 0; siz++) temp >>= 7;
                  // siz of 1st field
        for (count = siz, temp = val; siz-- != 0; val >>= 7)
            {
            b = (byte)((val & 0x7F) | ((temp != val)? 0x80 : 0));
            buf.setByte(b, siz);
            }           // now do next fields
        for (begin++; begin < end; begin++)
            {
            for (val = 0; begin < end && (b = bytes[begin]) != '.';
                val = (val * 10) + b - '0', begin++);
            if (val == 0) siz = 1;
            else for (temp = val, siz = 0; temp != 0; siz++) temp >>=7;
            for (count2 = count, count += siz, temp = val; siz-- != 0;
                val >>= 7)
                {
                b = (byte) ((val & 0x7F) | ((temp != val)? 0x80 : 0));
                buf.setByte(b, count2 + siz);
                }
            }
	ba.append(buf, count);
	return count;
	}

    protected int _csize(AsnByteArray from, int lth)
    {
        int counter = lth;
        int holder = from.getPtr();
        int start = holder;
        int end = (int)lth + start;
        int tlth;
        if (_type == AsnStatic.ASN_UNIVERSAL_STRING)
            return ((lth + 3) / 4);
        else if (_type == AsnStatic.ASN_BMP_STRING)
            return ((lth + 1) / 2);
        else if (_type == AsnStatic.ASN_UTF8_STRING)
        {
            for (counter = 0; start < end; counter++)
            {
                byte type;
                if ((from.index(start)==0xFE) || (from.index(start)==0xFF))
                    return -1;
                for (type=from.index(start), tlth=0; (type & 0x80)!=0; type <<= 1);
                for (start++; (tlth-- != 0) && ((from.index(start)& 0xC0)== 0x80);
                    start++);
                if ((tlth >= 0) || (start > end)) return -1;
            }
        }
        return counter;
    }

    protected int _dump_tag(AsnByteArray to, int tag, int offset, short flags, int mode)
    {
        //consider this carefully!
        int ansr, lth, cptr;
        AsnByteArray tagbuf = new AsnByteArray();
        int holder = to.getPtr();
        cptr = holder;
        int counter;
        String indef = "/* indefinite length */";
        for (counter = 0; (AsnStatic.typnames_typ[counter] != 0) &&
            (AsnStatic.typnames_typ[counter] < (tag & 0xFF)); counter++);
        if (AsnStatic.typnames_typ[counter] > (tag & 0xFF)) counter--;
        ansr = (AsnStatic.typnames_name[counter]).length();
        if ((mode & AsnStatic.ASN_READING) != 0)
        {
            String str = AsnStatic.typnames_name[counter];
            for (int i = 0; i < str.length(); i++)
                to.setByte((byte)str.charAt(i), cptr++);
        }
        if (AsnStatic.typnames_typ[counter] < AsnStatic.ASN_APPL_SPEC)
        {
            ansr++;
            if ((mode & AsnStatic.ASN_READING) != 0)
               to.setByte((byte)' ', cptr++);
            if (flags!=0)
            {
                ansr += 5 + offset + indef.length();
                if ((mode & AsnStatic.ASN_READING) != 0)
                {
                    for (int i = 0; i < indef.length(); i++)
                        to.setByte((byte)indef.charAt(i), cptr++);
                    cptr += newline(to, offset, cptr);
                }
            }
        }
        else
        {
            ansr += 3;
            if ((mode & AsnStatic.ASN_READING) != 0)
            {
                String str = "+0x";
                for (int i = 0; i < str.length(); i++)
                    to.setByte((byte)str.charAt(i), cptr++);
            }
            tag &= ~(AsnStatic.ASN_PRIV_SPEC);
            lth = _encode_tag(tagbuf, tag);
            ansr += 2*lth;
            if ((mode & AsnStatic.ASN_READING) != 0)
            {
                byte by;
                for (int bptr = 0; lth-- != 0; bptr++, cptr++)
                {
                    by = (byte)((tagbuf.index(bptr) >> 4) + '0');
                    if (by > '9') by += 7;
                    to.setByte(by, cptr);

                    by = (byte)((tagbuf.index(bptr) & 0xF) + '0');
                    if (by > '9') by += 7;
                    to.setByte(by, ++cptr);
                }
            }
            if (flags!=0)
            {
                ansr += indef.length();
                if ((mode & AsnStatic.ASN_READING) != 0)
                {
                    for (int i = 0; i < indef.length(); i++)
                        to.setByte((byte)indef.charAt(i), cptr++);
                }
            }
            ansr += 5 + offset;
            if ((mode & AsnStatic.ASN_READING) != 0)
                cptr += newline(to, offset, cptr);
        }
        return ansr;
    }

    private static int newline(AsnByteArray to, int offset, int start)
    {
        int holder = start;
        int begin = holder;
        to.setByte((byte)'\n', begin++);
        for (offset += 4; offset-- != 0; to.setByte((byte)' ', begin++));
        return (begin - holder);
    }

    protected int _dumpsize(AsnByteArray to, int offset, int mode)
    {
        //Check the cptr versus the to.incrPtr()!!!
        AsnObj obj;
        int extra, i, j;
        int ansr = 0;
        int holder = to.getPtr();
        int cptr = holder;
        //Step 1
        if (to == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        obj = _check_choice();
        if ((obj==null) && ((_flags & AsnStatic.ASN_OPTIONAL_FLAG)==0)) return -1;
        if ((i = obj._check_efilled(mode)) <= 0) return obj._read_empty(i, mode);
        if ((obj._supra!=null) && ((obj._supra._flags & AsnStatic.ASN_OF_FLAG)!=0)
            && (obj._next==null))  return 0;
        if (_type == AsnStatic.ASN_CHOICE)
        {
            if ((_tag != _type) && (_tag != AsnStatic.ASN_BOOLEAN) &&
                (((_flags & AsnStatic.ASN_DEFINED_FLAG)==0) ||
                ((_flags & AsnStatic.ASN_EXPLICIT_FLAG)!=0) ||
                (_tag < AsnStatic.ASN_APPL_SPEC)))
            {                /* a tagged CHOICE is implicitly tagged explicitly
                                and an explicitly tagged DEFINED needs the same,
                                as does a nonANY DEFINED */
                if (_tag != AsnStatic.ASN_BOOLEAN)  /* so _dumpsize 7 lines below won't repeat it */
                    ansr = _dump_tag(to, _tag, offset, (short)0, mode);
                if ((mode & AsnStatic.ASN_READING)!=0) to.incrPtr((int)ansr);
                if (((_flags & AsnStatic.ASN_DEFINED_FLAG)!=0) &&
                    (obj._type == AsnStatic.ASN_NOTASN1))
                    i = (int)obj._dumpread(to, offset + 4, mode);
                else i = (int)obj._dumpsize(to, offset + 4, mode);
                to.resetPtr();
                to.incrPtr(holder);
                if (i < 0) return i - ansr;
                ansr += i;
                return ansr;
            }
            else return obj._dumpsize(to, offset, mode);
        }

        //Step 2
        ansr += (j = _dump_tag(to, obj._tag, offset,
            (short)(obj._flags & AsnStatic.ASN_INDEF_LTH_FLAG), mode));
        extra = 4;
        if ((mode & AsnStatic.ASN_READING)!=0) cptr += j;
        if (obj._type == AsnStatic.ASN_NULL)
        {
            to.resetPtr();
            to.incrPtr(holder);
            return ansr;
        }
        if (((obj._flags & AsnStatic.ASN_EXPLICIT_FLAG)!=0) &&
            (obj._type != AsnStatic.ASN_CHOICE))
        {
            j = _dump_tag(to, obj._type, offset + extra,
                (short)(obj._flags & AsnStatic.ASN_SUB_INDEF_FLAG), mode);
            offset += 4;
            ansr += j;
            if ((mode & AsnStatic.ASN_READING)!=0) cptr += j;
        }

        //Step 3

        if (((obj._type & AsnStatic.ASN_CONSTRUCTED)!=0) && (obj._sub!=null))
        {
            int did, map_num, of = obj._flags & AsnStatic.ASN_OF_FLAG;
            did = map_num = 0;
            for(AsnObj sub = obj._sub; sub!=null; sub = sub._next, map_num++)
            {
                AsnObj tsub = sub;
                if ((of!=0) && (sub._next == null)) break;
                if ((sub._tag == AsnStatic.ASN_CHOICE) && (sub._tag == sub._type))
                    tsub = sub._check_choice();
                if ((did!=0) && (((sub._flags & AsnStatic.ASN_FILLED_FLAG)!=0) ||
                    (tsub._check_efilled(mode) > 0)))
                {      // active item > first
                    ansr += (5 + offset);
                    if ((mode & AsnStatic.ASN_READING)!=0) cptr += newline(to, offset, cptr);
                }
                if ((i = (int)tsub._dumpsize(to, offset + extra, mode)) < 0)
                {
                    _multi_stuff(map_num, obj);
                    to.resetPtr();
                    to.incrPtr(holder);
                    return (i - ansr);
                }
                did += i;
                ansr += i;
                if ((mode & AsnStatic.ASN_READING)!=0) cptr += i;
            }
            to.setByte((byte)0, cptr);
        }
        else ansr += obj._dumpread(to, offset + extra, mode);
        to.resetPtr();
        to.incrPtr(holder);
        return ansr;
    }

    protected int _dumpread(AsnByteArray to, int offset, int mode)
    {
        int holder = to.getPtr();
        int cptr = holder;
        int ansr = 0;
        int i,j=0;
        int count = 80 - offset - 2;  // # of printable spaces less "" or 0x
        int lth;
        if (_valp != null) lth = _valp.getLength();
        else lth = 0;
        ansr += lth;
        if ((_type == AsnStatic.ASN_NUMERIC_STRING) ||
            (_type == AsnStatic.ASN_PRINTABLE_STRING) ||
            (_type == AsnStatic.ASN_T61_STRING) ||
            (_type == AsnStatic.ASN_UTCTIME) ||
            (_type == AsnStatic.ASN_GENTIME))
        {
            for (i=0; i<lth; )
            {
                if ((mode & AsnStatic.ASN_READING ) != 0)
                    to.setByte((byte)'"', cptr++);
                for (j=count;(j-- != 0) && (i < lth);)
                {
                    to.setByte(_valp.index(i++), cptr);
                    if (to.index(cptr) == '"')
                    {
                        ansr++;
                        if ((mode & AsnStatic.ASN_READING ) != 0)
                        {
                            to.setByte((byte)'\\', cptr++);
                            to.setByte((byte)'"', cptr);
                        }
                    }
                    if ((mode & AsnStatic.ASN_READING ) != 0) cptr++;
                }
                if ((mode & AsnStatic.ASN_READING ) != 0) to.setByte((byte)'"', cptr++);
                ansr+=2;
                if (i<lth)
                {
                    ansr += (1+offset);
                    if ((mode & AsnStatic.ASN_READING ) != 0)
                    {
                        cptr += newline(to,offset-4,cptr);
                    }
                }
            }
        }
        else if (_type == AsnStatic.ASN_OBJ_ID)
        {
            ansr = ((AsnObjectIdentifier)this)._readsize(to, mode) - 1;
            if ((mode & AsnStatic.ASN_READING ) != 0) cptr += ansr;
        }
        else
        {
            if (count > 64) count = 32;
            else if (count > 32) count = 16;
            else count = 8;
            if ((_type == AsnStatic.ASN_BITSTRING) && (_sub != null))
            {
                char mask;
                while ((lth>1) && (_valp.index((int)lth-1)==0)) lth--;
                j=0;
                if (lth > 1)
                {
                    for (mask = (char)(_valp.index((int)lth-1)); ((mask & 1) == 0);
                        j++, mask >>>=1);
                }
            }
            ansr += lth;
            for (i=0; i<lth; )
            {
                if ((mode & AsnStatic.ASN_READING)!=0)
                {
                 //   c = cat(c, "0x");
                    to.setByte((byte)'0',cptr++);
                    to.setByte((byte)'x',cptr++);
                }
                ansr += 2;
                if (i==0 && _type == AsnStatic.ASN_BITSTRING && _sub!=null)
                {
                    byte temp1;
                    temp1 = (byte)((j >> 4) + '0');
                    if (temp1 > '9') temp1 += 7;
                    to.setByte(temp1, cptr);
                    if ((mode & AsnStatic.ASN_READING)!=0) cptr++;
                    temp1 = (byte)((j & 0xF) + '0');
                    if (temp1 > '9') temp1 += 7;
                    to.setByte(temp1, cptr);
                    if ((mode & AsnStatic.ASN_READING)!=0) cptr++;
                    j = count - 1;
                    i++;
                }
                else j = count;
                for ( ; j-- !=0  && i < lth; i++)
                {
                    byte temp2;
                    temp2 = (byte)((_valp.index(i) >> 4) + '0');
                    if (temp2 > '9') temp2 += 7;
                    to.setByte(temp2, cptr);
                    if ((mode & AsnStatic.ASN_READING)!=0) cptr++;
                    temp2 = (byte)((_valp.index(i) & 0xF) + '0');
                    if (temp2 > '9') temp2 += 7;
                    to.setByte(temp2, cptr);
                    if ((mode & AsnStatic.ASN_READING)!=0) cptr++;
                }
                if (i < lth)
                {
                    ansr += (1 + offset);
                    if ((mode & AsnStatic.ASN_READING)!=0)
                        cptr += newline(to, offset - 4,cptr);
                }
            }
        }
        to.setByte((byte)0,cptr);
        to.resetPtr();
        to.incrPtr(holder);
        return ansr;
    }

    protected int _encodesize(AsnByteArray to, int mode)
        {
        int holder = to.getPtr();
        int ptra, ptrb, ptrc, ptrd;
        int i;
        AsnObj obj;
        AsnByteArray toHolder = null;
        if (to == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        if ((mode & AsnStatic.ASN_READING) == 0)
          {
          toHolder = new AsnByteArray(to);
	  to = new AsnByteArray(32);
          }
        ptrc = holder;
        /* Step 1 */

        if ((obj = _check_choice()) == null) 
          return ((_flags & AsnStatic.ASN_OPTIONAL_FLAG) == 0) ? -1 : 0;
        if ((obj._supra != null) && ((obj._supra._flags & AsnStatic.ASN_OF_FLAG) != 0)
            && (obj._next == null))
            return asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
        if ((i = obj._check_efilled(mode)) <= 0)
            return obj._read_empty(i, mode);
        if (recursion == this) return asn_obj_err(AsnStatic.ASN_RECURSION_ERR);
        recursion = this;
        i = obj.constraint();
        recursion = null;
        if (i == 0) return asn_obj_err(AsnStatic.ASN_CONSTRAINT_ERR);
        /* Step 1a */
        if (_type == AsnStatic.ASN_CHOICE)
            {
            if ((_tag != _type) && (_tag != AsnStatic.ASN_BOOLEAN) &&
                (((_flags & AsnStatic.ASN_DEFINED_FLAG)==0) || ((_flags &
                AsnStatic.ASN_EXPLICIT_FLAG)!=0) || (_tag < AsnStatic.ASN_APPL_SPEC)))
                {
                ptrb = ptrc;
                ptrc += _encode_tag(to,_tag);
                if (((mode & AsnStatic.ASN_RE_SIZING)!=0) &&
                    ((obj._flags & AsnStatic.ASN_INDEF_LTH_FLAG)!=0))
                    to.setByte((byte)AsnStatic.ASN_INDEF, ptrc++);
                else to.setByte((byte)1, ptrc++);
		    to.resetPtr(ptrc);
                if (((_flags & AsnStatic.ASN_DEFINED_FLAG)!=0) &&
                    (obj._type == AsnStatic.ASN_NOTASN1))
                    i = obj._readsize(to, mode);
                else
                    {
                    if (_tag == AsnStatic.ASN_BITSTRING) 
                        to.setByte((byte)0, ptrc++);
  		    to.resetPtr(ptrc);
                    i = obj._encodesize(to, mode);
                    }
                if (i < 0)
                    {
  		    if (toHolder != null)
    		      {
		      to = null;
		      to = new AsnByteArray(toHolder);
		      toHolder = null;
    		      }
  		    to.resetPtr(holder);
  		    return (i - (holder - ptrc));
                    }
                if (((mode & AsnStatic.ASN_RE_SIZING)!=0) &&
                    ((obj._flags & AsnStatic.ASN_INDEF_LTH_FLAG)!=0))
                    {
                    to.setByte((byte)0, ptrc++);
                    to.setByte((byte)0, ptrc++);
                    }
                else 
                    {
  		    to.resetPtr(ptrc);
                    ptrc += _set_asn_lth(to, ptrc, ptrc + i, mode);
		    ptrc += i;
    		    }
		to.resetPtr(holder);
		if (toHolder != null) 
                    {
		    to = null;
		    to = new AsnByteArray(toHolder);
		    toHolder = null;
    		    }
                return (ptrc - holder);
                }
            else 
                {
  	        to.resetPtr(ptrc);
  	        return obj._encodesize(to, mode);
                }
            }
        else ptrb = 0;
        /* Step 2 */

        ptra = ptrc;
	to.resetPtr(ptrc);
        ptrc += obj._encode_tag(to, obj._tag);
        if (((mode & AsnStatic.ASN_RE_SIZING)!=0) &&
            ((obj._flags & AsnStatic.ASN_INDEF_LTH_FLAG)!=0))
            to.setByte((byte)AsnStatic.ASN_INDEF, ptrc++);
        else to.setByte((byte)0, ptrc++);
        if ((obj._flags & AsnStatic.ASN_EXPLICIT_FLAG)!=0)
            {
            if ((obj = obj._check_choice()) == null) 
                {/* in case it's defined by or ptr */
 	        if (toHolder != null) 
                    {
    		    to = null;
    		    to = new AsnByteArray(toHolder);
    		    toHolder = null;
      	            }
    	        return ((_flags & AsnStatic.ASN_OPTIONAL_FLAG) == 0) ? -1 : 0;
    	        }

            ptrd = ptrc;
	    to.resetPtr(ptrc);
            ptrc += obj._encode_tag(to, obj._type);
	    to.incrPtr(ptrc);
            if (((mode & AsnStatic.ASN_RE_SIZING)!=0) && ((obj._flags & AsnStatic.ASN_SUB_INDEF_FLAG)!=0))
                to.setByte((byte)AsnStatic.ASN_INDEF, ptrc++);
            else to.setByte((byte)1, ptrc++);
            }
        else ptrd = 0;
        /* Step 3 */
        to.resetPtr(ptrc);
        i = obj._readsize(to, mode);
        if (i < 0)
            {
	    to.resetPtr(holder);
	    if (toHolder != null) {
		to = null;
		to = new AsnByteArray(toHolder);
		toHolder = null;
	    }
            return (i - (ptrc - holder));
        }
        ptrc += i; // c += i
        /* Step 4 */

        if (ptrd != 0)
          {
          if (((mode & AsnStatic.ASN_RE_SIZING)!=0) && 
              ((obj._flags & AsnStatic.ASN_SUB_INDEF_FLAG) != 0))
              {
              to.setByte((byte)0, ptrc++);
              to.setByte((byte)0, ptrc++);
              }
          else 
              {
	      ptrc += _set_asn_lth(to, ptrd, ptrc, mode);
	      to.resetPtr(ptrc);
    	      }
   	   }
        if (((mode & AsnStatic.ASN_RE_SIZING)!=0) && ((obj._flags & AsnStatic.ASN_SUB_INDEF_FLAG)!=0))
          {
          to.setByte((byte)0, ptrc++);
          to.setByte((byte)0, ptrc++);
          }
        else 
          {
          ptrc += _set_asn_lth(to, ptra, ptrc, mode);
          to.resetPtr(ptrc);
      	  }

        /* Step 5 */
        if (ptrb != 0) 
          {
	  to.resetPtr(ptrb);
          ptrc += _set_asn_lth(to, ptrb, ptrc, mode);
	  to.resetPtr(ptrc);
	  }
        return (ptrc - holder);
        }

    protected int _encode_lth(AsnByteArray array, int to, int lth)
        {
        int ix = to;
        long tmp = 0;
        if (lth < 128) array.setByte((byte)lth, to);
        else
            {
            for (tmp = lth; tmp != 0; tmp >>= 8, ix++);
            tmp = ix - to;
            array.setByte((byte)(AsnStatic.ASN_INDEF_LTH + tmp), to);
            for ( ;ix > to; array.setByte((byte)(lth & 0xFF), ix--), lth >>= 8);
            }
        return (int)tmp + 1;
        }

    protected int _encode_tag(AsnByteArray to, int tag)
        {
        int holder = to.getPtr();
        int tmp = 0;
        to.setByteIncrPtr((byte)tag);
        if ((tag & AsnStatic.ASN_XT_TAG) == AsnStatic.ASN_XT_TAG)
            {
            for(tmp = tag >> 8; (tmp & AsnStatic.ASN_INDEF_LTH) != 0;
                to.setByteIncrPtr((byte)tmp), tmp >>= 8);
            to.setByteIncrPtr((byte)tmp);
            }
        return (to.getPtr() - holder);
        }

    protected int _enum_readsize(AsnByteArray to, int mode)
    {
        /*
        Function: Reads special enumerated cases
        Inputs:    Pointer to object
                   Pointer to buffer to fill
        Output: Filled buffer
        Procedure:
        1.IF parent is a bit string
                IF parent is not filled in
                IF default flag set for this, put 1 in answer
                ELSE put 0 in answer
            ELSE put value of requested bit in answer
            Return 1
          ELSE IF parent is an INTEGER OR ENUMERATED
            IF (parent is filled in AND parent's current value matches the tag) OR
                (parent is not filled in AND default flag set for this item),
                    put item's tag in answer
          ELSE return -1
        */
        AsnObj superp = _supra;
        AsnIntRef ref = new AsnIntRef(0);
        AsnByteArray buf = new AsnByteArray(4);
        if (mode < AsnStatic.ASN_READING) to = buf;  // zero is sizing or vsizing (valuesize)
                                          // just return the size of data, not returning any to data
        int holder = to.getPtr();// c = to, save the to pointer
        int tmp = holder;
        if (superp._type == AsnStatic.ASN_BITSTRING)
          {
            if ((superp._flags & AsnStatic.ASN_FILLED_FLAG)==0)
            {
                if ((_flags & AsnStatic.ASN_DEFAULT_FLAG)!=0)
                  {
                  to.setByteIncrPtr((byte)1);
                  }
                else
                  {
                  to.setByteIncrPtr((byte)0);
                 }
            }
            else if (((_tag >>> 3) + 1) >= superp._valp.getLength()) to.setByteIncrPtr((byte)0);
            else to.setByteIncrPtr((byte)((((superp._valp).index((int)(_tag >>> 3) + 1)) >>> (7 - (_tag & 7))) & 1));
            //check above casting with Charlie
            tmp = to.getPtr();
        }
        else if (superp._type == AsnStatic.ASN_INTEGER
            || superp._type == AsnStatic.ASN_ENUMERATED)
        {
            superp.read(ref);

            if ((((superp._flags & AsnStatic.ASN_FILLED_FLAG)!=0) &&
                (ref.val == _tag)) ||
                (((superp._flags & AsnStatic.ASN_FILLED_FLAG)==0) &&
                ((_flags & AsnStatic.ASN_DEFAULT_FLAG)!=0)))
            putx(to, _tag);
            tmp = to.getPtr();
        }
        else tmp--;
        return (tmp - holder);
    }


    private static void putx(AsnByteArray to, int val)
    {
        int tmp = val >> 8;
        if (tmp!=0) putx(to, tmp);
        to.setByteIncrPtr((byte)(val & 0xFF));
    }

    protected void _fill_upward(int filled)
    {
        AsnObj superp, subp;
        _flags |= filled;
        for (subp=this, superp = _supra; superp!=null; subp=superp, superp = superp._supra)
        {
            if ((superp._type == AsnStatic.ASN_CHOICE) &&
                ((superp._flags & AsnStatic.ASN_FILLED_FLAG)==0))
            {
                if (((superp._flags & AsnStatic.ASN_DEFINED_FLAG)!=0) &&
                    ((subp._flags & AsnStatic.ASN_CHOSEN_FLAG)==0))
                    asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
                else
                {
                    for (AsnObj tobjp = superp._sub; tobjp!=null; tobjp=tobjp._next)
                        {
                        if (tobjp != subp) tobjp._clear(-1);
                        }
                }
            }
            if (superp._type == AsnStatic.ASN_SET &&
                ((superp._flags & AsnStatic.ASN_OF_FLAG) == 0))
            {
                ((AsnSet)superp).add_link(subp);
            }
            superp._flags |= filled;

            if (filled == 0)
            {
                for (subp = superp._sub; subp != null && ((subp._flags &
                    AsnStatic.ASN_FILLED_FLAG) == 0); subp = subp._next);
                if (subp == null)
                    superp._flags &= ~(AsnStatic.ASN_FILLED_FLAG);
                else
                    break;
            }
        }
    }

    // Need to modify to take the start position
    protected int _find_lth(AsnByteArray buf, int startPtr)
    {
        int holder = buf.getPtr();  //original position - must be set back to this before return
        buf.resetPtr(startPtr);
        int lth =_find_lth(buf);
        buf.resetPtr(holder);

        return lth;
    }

    protected int _find_lth(AsnByteArray buf)
    {
        int lth=0;
        int holder = buf.getPtr();  //original position - must be set back to this before return
        //AsnByteArray tempbuf = (AsnByteArray)buf.clone();
        decode_asn_tag(buf);     /*  points to length */

        if (buf.index() == AsnStatic.ASN_INDEF_LTH)
          buf.incrPtr();
        else
        {
            if (buf.index() > 0x84)
            {
                asn_obj_err(AsnStatic.ASN_LENGTH_ERR);
                return (holder - buf.getPtr());
            }
            lth = decode_asn_lth(buf);  //now points to start of contents
            int lthHolder = buf.getPtr(); //hold value of ptr
            buf.resetPtr(holder);
            return (lthHolder + lth) - holder;  // definite lenght return
        }
        if ((buf.index(holder) & AsnStatic.ASN_CONSTRUCTED)==0) {
          buf.resetPtr(holder);
          return -1;
        }
        for ( ;(buf.index()!=0) || (buf.index(buf.getPtr()+1)!=0); buf.incrPtr((int)lth))
        {
            lth = _find_lth(buf);
            if (lth < 0) {
              buf.resetPtr(holder);
              return (lth - (buf.getPtr() - holder));
            }
        }
        buf.resetPtr(holder);
        return (buf.getPtr() + 2) - holder; /* length of tag + lth + contents + double null */
    }

    protected int _get_asn_time(AsnByteArray from, int lth)
    {
        AsnByteArray temp;
        int val;
        int year, month, day, hour, minute, second;
        int begin = from.getPtr();
        int holder = begin;
        int end = begin + lth;
        for ( ;(begin<end) && (from.index(begin) >= '0') &&
            (from.index(begin) <= '9'); begin++);
        if (begin < end && (begin < (holder + AsnStatic.UTCSE) ||
            ((from.index(begin) != 'Z') && (from.index(begin) != '+') &&
            (from.index(begin) != '-')) ||
            ((from.index(begin) == 'Z') && (end != begin + AsnStatic.UTCSFXHR)) ||
            ((from.index(begin) < '0') && (end != begin + AsnStatic.UTCSFXMI + AsnStatic.UTCMISIZ))))
            return 0xFFFFFFFF;

        temp = new AsnByteArray(from);
        temp.incrPtr(AsnStatic.UTCYR);
        year = (int)(get_num(temp, AsnStatic.UTCYRSIZ) - AsnStatic.UTCBASE);
        if (year<0) year+=100;

        temp.resetPtr();
        temp.incrPtr(holder + AsnStatic.UTCMO);
        month = (int)(get_num(temp,AsnStatic.UTCMOSIZ));
        if (month < 1 || month > 12) return 0xFFFFFFFF;

        val = (year * 365) + AsnStatic._mos[month-1] + ((year + (AsnStatic.UTCBASE % 4))/4) -
            (((((year + AsnStatic.UTCBASE) % 4) == 0) && (month < 3))?1:0);

        temp.resetPtr();
        temp.incrPtr(holder + AsnStatic.UTCDA);
        day = (int)(get_num(temp,AsnStatic.UTCDASIZ));
        if ((day < 1) || (day > AsnStatic._mos[month] - AsnStatic._mos[month - 1] +
            (((((year + AsnStatic.UTCBASE) % 4) == 0) && (month == 2))?1:0)))
            return 0xFFFFFFFF;
        val += day - 1;

        if (holder + AsnStatic.UTCHR >= end) return 0xFFFFFFFF;
        temp.resetPtr();
        temp.incrPtr(holder + AsnStatic.UTCHR);
        hour = (int)(get_num(temp,AsnStatic.UTCHRSIZ));
        if (hour > 23) return 0xFFFFFFFF;
        val = val*24 + hour;

        if (holder + AsnStatic.UTCMI >= end) return 0xFFFFFFFF;
        temp.resetPtr();
        temp.incrPtr(holder + AsnStatic.UTCMI);
        minute = (int)(get_num(temp,AsnStatic.UTCMISIZ));
        if (minute > 59) return 0xFFFFFFFF;
        val = val*60 + minute;

        //seconds are optional in reading in time
        if (begin > holder + AsnStatic.UTCSE)
        {
            temp.resetPtr();
            temp.incrPtr(holder + AsnStatic.UTCSE);
            second = (int)(get_num(temp,AsnStatic.UTCSESIZ));
            if (second > 59) return 0xFFFFFFFF;
        }
        else second = 0;
        val = val*60 + second;

        if ((from.index(begin) == '+') || (from.index(begin) == '-'))
        {
            temp.resetPtr();
            temp.incrPtr(begin + AsnStatic.UTCSFXHR);
            int sfxhr = (int)(get_num(temp,AsnStatic.UTCHRSIZ));
            temp.resetPtr();
            temp.incrPtr(begin + AsnStatic.UTCSFXMI);
            int sfxmi = (int)(get_num(temp,AsnStatic.UTCMISIZ));
            if (sfxhr > 23 || sfxmi > 59) return 0xFFFFFFFF;
            int tempval = sfxhr*60 + sfxmi;
            if (tempval > 720) return 0xFFFFFFFF;
            if (from.index(begin) == '+') tempval = -tempval;
            val += (60*tempval);
        }

        return val;
    }

    protected AsnObj _go_down()
    {
        return _sub;
    }

    protected AsnObj _go_up()
    {
        return _supra;
    }

    protected AsnObj _go_next()
    {
        return _next;
    }

    public int numitems()
        {
        int count = 0;
        AsnObj obj;
        if ((_flags & AsnStatic.ASN_OF_FLAG) == 0)
            return asn_obj_err(AsnStatic.ASN_NOT_OF_ERR);
        for (obj = _sub; obj._next != null; obj = obj._next, count++);
        return count;
        }

    protected int _insert()
        {
        int index;
        AsnObj obj, prev, sub;
        AsnOf sup = new AsnOf();
        AsnArrayOfOfs suparray;
        if ((_supra == null) || ((_supra._flags & AsnStatic.ASN_OF_FLAG) == 0))
            return asn_obj_err(AsnStatic.ASN_NOT_OF_ERR);
        if (_supra._max != 0 && _supra.numitems() >= _supra._max)
            return asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
        obj = (AsnObj)_dup();
        if ((obj._flags & AsnStatic.ASN_DEFINED_FLAG)!=0)
            {
            for (prev=_supra._sub._sub, sub=obj._sub; (prev!=null) && (sub!=null);
                prev=prev._next, sub=sub._next)
                {
                sub._flags |= (prev._flags & AsnStatic.ASN_CHOSEN_FLAG);
                }
            }
        if (_supra._sub == this)
            {
            index=0;
            obj._next = _supra._sub;
            _supra._sub = obj;
            }
        else
            {
            for (index = 1, prev = _supra._sub; (prev._next!=null) && (prev._next!=this);
                prev=prev._next, index++);
            obj._next=prev._next;
            prev._next=obj;
            }
        return index;
    }

    protected AsnObj _index_op(int index)
    {
        AsnObj objp;
        if ((_supra == null) ||
            ((_supra._flags & AsnStatic.ASN_OF_FLAG) == 0))
        {
            asn_obj_err(AsnStatic.ASN_NOT_OF_ERR);
            return (AsnObj)this;
        }
        if (_next == null)
            objp = (AsnArray)(_supra._sub);
        else
            objp = (AsnObj)this;
        for ( ; (index-- != 0) && (objp._next != null); objp = (AsnArray)(objp._next));
        if (index >= 0)
            asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
        return objp;
    }

    private int _is_default()
    {
        //only called from check_efilled
        AsnByteArray buf = new AsnByteArray(4);
        if (_type == AsnStatic.ASN_BOOLEAN)
        {
            AsnBoolean obj = (AsnBoolean)this;
            int val = (obj._get_def() & AsnStatic.BOOL_DEFAULT);
            byte first = _valp.index(0);
            if (((first==0) && (val==0)) || ((first!=0) && (val!=0))) return 1;
            return 0;
        }
        if ((_type & AsnStatic.ASN_CONSTRUCTED)!=0)
            return ((_readsize(buf, 0)==0) ? 1 : 0);
        if ((_type == AsnStatic.ASN_ENUMERATED) || (_type == AsnStatic.ASN_INTEGER))
            {
            AsnIntRef ref = new AsnIntRef(0);
	    int def;
            if (read(ref) < 0) return -1;
	    if (_type == AsnStatic.ASN_ENUMERATED)
                def = ((AsnEnumerated)this)._default;
	    else def = ((AsnInteger)this)._default;
            return ((ref.val == def)? 1: 0);
            }
        if (_type == AsnStatic.ASN_BITSTRING)
            return ((_valp.getLength() <=1) ? 1 : 0);
        return 0;
    }

    protected int _match(AsnByteArray start, int end)
        {
        int startHolder = start.getPtr(); // == sp
        int bPtr;  // beginning of the contents pointer == bp
        int cPtr;  // Pointer to follow start string == cp = start.getPtr()
        byte c;    // the byte cPtr pointing in start AsnByteArray == *cp =start.index()
        int ePtr = 0; // ep

        int err = 0, indef = 0;
        int lth = 0, tlth;
        AsnObj obj, sub, tobj; // objp, subp, tobjp
        int tag;
        int[] map_buf = new int[20];
        int map_index = 0;
        map_buf[map_index] = 0;
        map_buf[1] = -1;

        /* Step 1 */

        if ((tag = decode_asn_tag(start)) != _tag &&    // cPtr at length
                    (_tag != (tag & ~(AsnStatic.ASN_CONSTRUCTED)) ||
            _type >= AsnStatic.ASN_SEQUENCE))
            {

            }
        /* Step 2 */
        if ((c = start.index()) != AsnStatic.ASN_INDEF_LTH)
        {   // item is definite length
            if (c > 0x84 || (lth = decode_asn_lth(start)) < 0 || // cPtr at contents
             (start.getPtr() + lth) > end)
                err = AsnStatic.ASN_LENGTH_ERR;
        }
        else if ((tag & AsnStatic.ASN_CONSTRUCTED) == 0)  // item is primitive
            err = AsnStatic.ASN_CODING_ERR;
        else
            {
            start.incrPtr();                        // cPtr at contents
            lth = _find_lth(start, startHolder) - (start.getPtr() - startHolder);
            indef += 2;
            _flags |= AsnStatic.ASN_INDEF_LTH_FLAG;
            }
        /* Step 3 */
        obj = this;
        while ((err == 0) &&
            (((obj._flags & AsnStatic.ASN_EXPLICIT_FLAG)!=0 && (obj._tag & AsnStatic.ASN_CONSTRUCTED)!=0) ||
            (obj._type == AsnStatic.ASN_CHOICE &&
            ((obj._flags & AsnStatic.ASN_DEFINED_FLAG)==0 || obj._tag != AsnStatic.ASN_BOOLEAN))))
            {
        bPtr = start.getPtr();
        if ((obj._flags & AsnStatic.ASN_DEFINED_FLAG)!=0)
            { // it's a DEFINED BY
            for (sub = obj._sub; (sub!=null) && (sub._flags & AsnStatic.ASN_CHOSEN_FLAG)==0;
                sub = sub._next);
            if (sub == null) // no sub-member has been chosen
                return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
            if (sub._type == AsnStatic.ASN_NOTASN1)
                {  // sub not ASN.1
	        if ((lth = obj._write(start, lth)) < 0) 
                   return (startHolder - (start.getPtr() - lth));
	        return ((start.getPtr() + lth) - startHolder); // (&cp[lth] - sp);
                }
            if (obj._tag == AsnStatic.ASN_BITSTRING)
                start.incrPtr(); // skip over the null
            }
        tag = decode_asn_tag(start);    // cPtr at length of sub-field
        lth = 0;
        if ((obj._type != AsnStatic.ASN_CHOICE && tag != obj._type) ||
            (obj._type == AsnStatic.ASN_CHOICE &&
            (obj = obj._tag_search(tag, map_buf, 0)) == null))
            {
                buf_stuff(map_buf);
                obj.asn_obj_err(AsnStatic.ASN_MATCH_ERR);
                return(startHolder - start.getPtr()); //sp - cp;
            }
        if ((c = start.index()) != AsnStatic.ASN_INDEF_LTH)
            {
            if (c > 0x84 || (lth = decode_asn_lth(start)) < 0 || // cPtr at contents
                (start.getPtr() + lth) > end)
                err = AsnStatic.ASN_LENGTH_ERR;
            }
        else if ((tag & AsnStatic.ASN_CONSTRUCTED)==0)
            err = AsnStatic.ASN_CODING_ERR;
        else
            {
            start.incrPtr(); //cp++;    cPtr at contents
            lth = _find_lth(start, bPtr) - (start.getPtr() - bPtr);
            indef += 2;
            _flags |= AsnStatic.ASN_SUB_INDEF_FLAG;
            }
            if (obj._type != AsnStatic.ASN_CHOICE && tag == obj._type) break;
            if (obj != this)
                {
                while(map_buf[map_index] >= 0) map_index++;
                map_buf[map_index] = 0;
		map_buf[map_index + 1] = -1;
                }
            }
        if (err != 0)
            {
            asn_obj_err(err);
            return (startHolder - start.getPtr());
            }
        if (indef==0)
            ePtr = start.getPtr() + lth;  // ep
           // step 4
   
        if ((tag & AsnStatic.ASN_CONSTRUCTED)!=0 && tag < AsnStatic.ASN_APPL_SPEC &&
          obj._type < AsnStatic.ASN_SEQUENCE && obj._type != AsnStatic.ASN_ANY)
	  {
          int first;
          for (first = 1;
            err==0 && ((ePtr!=0 && start.getPtr() < ePtr) || (ePtr==0 && start.index()!=0));
	       start.incrPtr(lth))
            {
            //if (*cp++ != obj._type || *cp == AsnStatic.ASN_INDEF_LTH) err = AsnStatic.ASN_MATCH_ERR;
            if ((start.indexIncrPtr() & 0xFF) != obj._type || start.index() == AsnStatic.ASN_INDEF_LTH)
              // cPtr on length
              err = AsnStatic.ASN_MATCH_ERR;
            else if (start.index() > 0x84)
              err = AsnStatic.ASN_LENGTH_ERR;
            else
              {
              lth = decode_asn_lth(start);
              if ((first!=0 && (lth = obj._write(start, (int)lth)) < 0) ||
		  (first==0 && (lth = obj._append(start, lth)) < 0))
  		  return (startHolder - (start.getPtr() - lth));
              first = 0;
              }
            } //for
          if (err==0 && obj.vsize() < obj._min)
            err = AsnStatic.ASN_BOUNDS_ERR;
          if (err!=0)
            {
            asn_obj_err(err);
            return (startHolder - start.getPtr());
            }
          start.incrPtr(indef); // += indef;
	  } // if ((tag & AsnStatic.ASN_CONSTRUCTED)
	else if ((tag & AsnStatic.ASN_CONSTRUCTED)==0 || obj._sub == null)
	  {
	    if ((tlth = obj._write(start, lth)) <= 0 && lth != 0) {
              start.resetPtr(startHolder);
	      return (startHolder - (start.getPtr() - tlth));
	    }
          if (obj._type == AsnStatic.ASN_ANY)
            obj._tag = tag;
          start.incrPtr(tlth);
          }
        else if (lth == 0) obj.write(start, lth);
        else
          {
          int of = (obj._flags & AsnStatic.ASN_OF_FLAG);
          int currPtr = start.getPtr();
          for (sub = obj._sub;
            err == 0 && sub != null && ((ePtr != 0 && start.getPtr() < ePtr) ||
            (ePtr == 0 && start.index() != 0)); sub = sub._next)
            {
	    AsnObjRef objref = new AsnObjRef();
	    objref.obj = sub;
            tobj = sub._tag_scan(objref, start, of, map_buf, map_index);
	    sub = objref.obj;
            lth = 0;
            if (tobj==null || sub==null)
              err = AsnStatic.ASN_MATCH_ERR;
            else if (of != 0 && obj._max != 0 && map_buf[map_index] >= obj._max)
              err = AsnStatic.ASN_OF_BOUNDS_ERR;
            else if ((lth = tobj._match(start, ePtr)) < 0) 
              err = AsnStatic.ASN_MATCH_ERR;
            else
              {
              start.incrPtr(lth); // now at next tag
              map_buf[map_index]++;
	      map_buf[map_index + 1] = -1;
              }
            if (sub==null) break;
            }
          if (err==0)
            {
            if (of==0)
              {
              if (obj._type == AsnStatic.ASN_SET)
                {
                map_buf[0] = 0;
                map_buf[1] = -1;
                for (sub = obj._sub;
                  sub!=null && (sub._flags & (AsnStatic.ASN_FILLED_FLAG | AsnStatic.ASN_OPTIONAL_FLAG))!=0;
                  sub = sub._next, map_buf[0]++);
                }
              for ( ; sub!=null && err==0; sub = sub._next)
                {
                if ((sub._flags & AsnStatic.ASN_DEFINED_FLAG) !=0)
                  {
                  for (tobj = sub._sub;
                    tobj!=null && (tobj._flags & AsnStatic.ASN_CHOSEN_FLAG)==0;
                    tobj = tobj._next);
                  }
                else tobj = sub;
                if (tobj==null)
                  err = AsnStatic.ASN_NO_DEF_ERR;
                else if ((tobj._flags & AsnStatic.ASN_OPTIONAL_FLAG)==0 &&
                  (sub._flags & AsnStatic.ASN_OPTIONAL_FLAG)==0 &&
                  tobj._type != AsnStatic.ASN_NONE)  // defined things only
                  err = AsnStatic.ASN_MANDATORY_ERR;
                if (err!=0)
                  lth = 0;
                } // for
              } // if (!of)
            else if (map_buf[map_index] < obj._min)
              err = asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
          } // if (!err)
        if (err==0 && obj.constraint()==0)
          asn_constraint_ptr = currPtr+1; //&curr_ptr[1];
        if (err!=0)
          {
          buf_stuff(map_buf);
          if (lth == 0) asn_obj_err(err);
          else if (lth < 0) start.decrPtr(lth);
          cPtr = start.getPtr();
          start.resetPtr(startHolder);
          return (startHolder - cPtr);
          }
       start.incrPtr(indef); //cp += indef;
      }
      cPtr = start.getPtr();
      start.resetPtr(startHolder);
    return (cPtr - startHolder);

   }

    protected int _map(AsnByteArray array, int row, int col)
    {
        AsnObj obj;
        int lth;
        int bPtr, ePtr;
        int cPtr = array.getPtr();
        boolean tieback = false;
        //int addr =
        if (row >= AsnStatic.ARRAY_SIZE - 2)
        {
            //memset(array[AsnStatic.ARRAY_SIZE - 1], '*', AsnStatic.LINE_SIZE - 1);
            return col;
        }
        if ((_supra!=null) && (_supra._tag == AsnStatic.ASN_CHOICE) &&
            ((_flags & AsnStatic.ASN_FILLED_FLAG)==0))
        {
            /* rub out address of orig obj */
            col -= 6;
            /* so orig obj address will be replaced by first filled item */
            tieback = false;
        }
        else tieback = true;
        if ((_supra!=null) && (_supra._sub == this))
        {
            for (obj = _next; obj != null; obj = obj._next)
            {
                if ((_supra != null) && ((_supra._tag == AsnStatic.ASN_CHOICE &&
                    ((obj._flags & AsnStatic.ASN_FILLED_FLAG)==0)) ||
                    (((_supra._flags & AsnStatic.ASN_OF_FLAG)!=0) &&
                    (obj._next == null) && ((obj._flags & AsnStatic.ASN_FILLED_FLAG)==0))))
                    continue;
                col += 6;
                cPtr = row + col;
                if (col >= 78)
                {
                    //*c = '>';
                    return col - 6;
                }
                else
                {
                    col = obj._map(array, row, col);
                    //if (tieback && *c > ' ')
                    //    for (e = array[row]; *(--c) <= ' ' && c > e; *c = '-');
                }
            }
        }
        return col;
    }

    protected void _multi_stuff(int map_num, AsnObj low)
    {
        stuff(map_num);
        if (_supra != null)
        {
            if (_supra._type == AsnStatic.ASN_CHOICE)
            {
                AsnObj choice = _supra;
                int iter = 0;
                for (AsnObj tobj = choice._sub; (tobj != null) && (tobj != low);
                    iter++, tobj = tobj._next);
                stuff(iter);
            }
        }

    }

    protected int _put_asn_time(AsnByteArray to, int time)
    {
        int year, month, day, hour, minute, second;
        int holder = to.getPtr();

        second = (time % 60);
        time /= 60;
        minute = (time % 60);
        time /= 60;
        hour = (time % 24);

        to.incrPtr(AsnStatic.UTCSE);
        put_num(to, second, AsnStatic.UTCSESIZ);
        to.resetPtr();
        to.incrPtr(holder + AsnStatic.UTCMI);
        put_num(to,minute,AsnStatic.UTCMISIZ);
        to.resetPtr();
        to.incrPtr(holder + AsnStatic.UTCHR);
        put_num(to,hour,AsnStatic.UTCHRSIZ);

        time /= 24;
        time += (((AsnStatic.UTCBASE-1)%4)*365);
        day = (time % 1461); //number of days in quadrenniad
        time /= 1461;

        year = ((time * 4) + ((day == 1460)? 3 :
                        (day / 365)) - ((AsnStatic.UTCBASE - 1) % 4));
        if (day == 1460) day = 365;
        else day %= 365;
        for (month = 0; day >= AsnStatic._mos[(int)month]; month++);
        if (month > 12) month--;
        if ((year%4) == (AsnStatic.UTCBASE % 4)) //leap year
        {
            if (day == 59) month--; //Feb. 29
            else if ((day > 59) && ((day -= 1) < (AsnStatic._mos[(int)month-1]))) month--;
        }

        to.resetPtr();
        to.incrPtr(holder + AsnStatic.UTCDA);
        put_num(to,day + 1 - AsnStatic._mos[(int)month-1],AsnStatic.UTCDASIZ);
        to.resetPtr();
        to.incrPtr(holder + AsnStatic.UTCMO);
        put_num(to, month, AsnStatic.UTCMOSIZ);
        to.resetPtr();
        to.incrPtr(holder + AsnStatic.UTCYR);
        put_num(to,year + AsnStatic.UTCBASE ,AsnStatic.UTCYRSIZ);

        to.resetPtr();
        to.incrPtr(holder + AsnStatic.UTCSE + AsnStatic.UTCSESIZ);
        int newHolder = to.getPtr();
        to.setByte((byte)'Z', newHolder++);

        to.resetPtr();
        to.incrPtr(holder);
        return (newHolder - holder);
    }

    protected int _read_empty(int i, int mode)
    {
        if (i<0)
        {
            if ((mode & AsnStatic.ASN_READING)!=0)
                i = asn_obj_err(AsnStatic.ASN_MANDATORY_ERR);
            else
            {
                i=0;
                error.setErrorNo(AsnStatic.ASN_MANDATORY_ERR);
            }
        }
        return i;
    }

    protected int _readsize(AsnByteArray to, int mode)
    {
        int holder = to.getPtr(); // save the initial pointer
        int i;
        int of = 0;
        int map_num;
        int size=0;
        // uchar *c, mask, buf[8];
        AsnObj obj;
        AsnObj sub;
        AsnUTCTime timeobj = new AsnUTCTime(); //??
        if (to == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        if ((mode & AsnStatic.ASN_READING) == 0) to = new AsnByteArray(8); 
        int ptrc = holder;

        /* Step 1 */
        if ((obj = _check_choice()) == null)
            return ((_flags & AsnStatic.ASN_OPTIONAL_FLAG)==0) ? -1 : 0;
        if ((obj._supra != null) && ((obj._supra._flags & AsnStatic.ASN_OF_FLAG)!=0) &&
            (obj._next == null))
            return asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
        if ((i = obj._check_vfilled()) <= 0)
            {
            if ((i == 0) && (((obj._flags & AsnStatic.ASN_DEFAULT_FLAG)!=0) ||
                (((obj._flags & AsnStatic.ASN_CHOSEN_FLAG)!=0) && (obj._supra != null)
                && ((obj._supra._flags & AsnStatic.ASN_DEFAULT_FLAG)!=0))))
                {
		AsnIntRef ref = new AsnIntRef(0);
                i = obj.read(ref);
                for (of = i; --of >= 0; 
                    to.setByte((byte)(ref.val & 0xFF), of + holder), ref.val >>=8);
		to.resetPtr(holder);
                return i;
                }
            return obj._read_empty(i, mode);
            }
        if ((obj._type == AsnStatic.ASN_NULL) || 
            ((obj._type == AsnStatic.ASN_ANY) &&
	    (obj._tag == AsnStatic.ASN_NULL))) return 0;

        /* Step 2 */
        if (((obj._type & AsnStatic.ASN_CONSTRUCTED) == 0) || (obj._sub == null) ||
            ((obj._flags & AsnStatic.ASN_TABLE_FLAG) != 0))
            {
            if (obj._valp != null) size = obj._valp.getLength();
            else return 0;
            if (obj._type == AsnStatic.ASN_BOOLEAN)
                {
                to.setByte(obj._valp.index(0), ptrc);
                if ((mode == AsnStatic.ASN_READING) && (to.index(ptrc) != 0))
                    to.setByte((byte)0xFF, ptrc);
                return 1;
                }
            else if ((mode < AsnStatic.ASN_RE_SIZING) && ((obj._type == AsnStatic.ASN_UTCTIME)
                || (obj._type == AsnStatic.ASN_GENTIME)))
                {
                int dtime = obj._valp.getLength();
                AsnByteArray ctime = new AsnByteArray(obj._valp); //clone or just = ???  clone I think
                if (obj._type == AsnStatic.ASN_GENTIME)
                    {
                    ctime.incrPtr(2);
                    dtime -= 2;
                    }
                dtime = obj._get_asn_time(ctime, (int)dtime);
                if (dtime == 0xFFFFFFFF)  
		  return asn_obj_err(AsnStatic.ASN_TIME_ERR);
                ctime = new AsnByteArray(AsnStatic.UTCSE+6);
                if (obj._type == AsnStatic.ASN_UTCTIME)
                    size = obj._put_asn_time(ctime,dtime);
                else
                    {
                    ctime.incrPtr(2);
                    size = 2 + obj._put_asn_time(ctime,dtime);
                    ctime.decrPtr(2);
                    int tempptr = ctime.getPtr();
                    if (ctime.index(tempptr + 2) < '7')
                        {
                        ctime.setByte((byte)'2');
                        ctime.setByte((byte)'0', tempptr + 1);
                        }
                    else
                        {
                        ctime.setByte((byte)'1');
                        ctime.setByte((byte)'9', tempptr + 1);
                        }
                    }
                timeobj._valp = ctime;
                obj = timeobj;
                }
            if ((obj._type == AsnStatic.ASN_BITSTRING) && (mode <= AsnStatic.ASN_READING)
                && (obj._sub != null))
                {
                while (size > 1 && (obj._valp.index((int)(size - 1)) == 0))
                    size--;
                i = 0;
                if (size > 1)
                    {
                    byte mask;
                    for (mask = obj._valp.index(size - 1); (mask & 1) == 0;
                        i++, mask >>>= 1);  // >>> or >> ????????
                    }
                to.setByte((byte)i, ptrc++);
                i = 1;
                if ((mode & AsnStatic.ASN_READING)==0) return size;
                else size--;
                }
            else i = 0;
            if ((mode & AsnStatic.ASN_READING) != 0)
                {
                for ( ; size-- != 0 ; to.setByte(obj._valp.index(i++), ptrc++));
                if ((obj._type == AsnStatic.ASN_BITSTRING) && (mode <= AsnStatic.ASN_READING))
                    {
                    if (ptrc > holder)
                        {
                        byte mask1 = (byte) ~((1 << to.index(holder)) - 1);
                        if (i > 1)
                            to.setByte((byte) (to.index(ptrc-1) & mask1), ptrc - 1);
                        }
                    else to.setByte((byte)0, holder);
                    }
                size = ptrc- holder;
                }
	    to.resetPtr(ptrc);
            return size;
            }
        of = obj._flags & AsnStatic.ASN_OF_FLAG;
        map_num = 0;
        size = 0;
        /* Step 2a */
        if ((mode == AsnStatic.ASN_READING) && (obj._type == AsnStatic.ASN_SET))
            {
            TagTable[] table;
            int lx, ex;
            int count;
            AsnObj nobj;

            for (ex = 0, sub = obj._sub; sub != null; sub = sub._next)
                {
                if (((sub._flags & AsnStatic.ASN_FILLED_FLAG) != 0) ||
                    ((of != 0) && (sub._next != null))) ex++;
                /* above doesn't count the last 'guard' item, but does count
                the case where there is a single item marked filled because a
                lower item was filled */
                }
            table = new TagTable[ex];  
            for(lx = 0, sub = obj._sub; lx < ex; lx++, sub = sub._next)
                {
		AsnByteArray bufs = new AsnByteArray(8);
		int lth;
		TagTable tagt;
		tagt = table[lx] = new TagTable();
                if (((sub._flags & AsnStatic.ASN_FILLED_FLAG) == 0) &&
                    (of == 0 || sub._next == null))   continue;
                nobj = sub._check_choice();   // sub might be CHOICE
		tagt.lth = nobj.size();
                tagt.orig = lx;
                tagt.obj = nobj;
                lth = nobj._encode_tag(bufs, nobj._tag);
		for (int ix = 0; lth-- != 0; 
                    tagt.tag = (tagt.tag << 8) + bufs.index(ix++));
                }
            /* bubble sort */
            for (lx = 0; lx < ex - 1; )
                {
		TagTable ttagt = table[lx];
		TagTable ntagt = table[lx + 1];
		int swap = 0;
		if (ttagt.tag > ntagt.tag) swap = 1;
		else if (ttagt.tag == ntagt.tag)
		    {
		    if (ttagt.lth > ntagt.lth ||
		        (ttagt.lth == ntagt.lth &&
			ttagt.obj.greaterThan(ntagt.obj))) swap = 1;
		    }
                if (swap > 0)
                    {
		    table[lx + 1] = ttagt;
		    table[lx] = ntagt;
		    if (lx > 0) lx--;
                    }
                else lx++;
                }
            for (lx = 0, size = 0; lx < ex; lx++)
                {
		TagTable tagt = table[lx];
		i = tagt.obj._encodesize(to, mode);
                if (i < 0)
                    {
                    _multi_stuff(tagt.orig, obj);
                    return (i - size);
                    }
		size += i;
                }
	    }
        else if ((mode == AsnStatic.ASN_RE_READING) && (obj._type == AsnStatic.ASN_SET) && (of == 0))
            {
            AsnLink relinkp;
            for (relinkp = ((AsnSet)obj)._relinksp; relinkp != null;
                relinkp = relinkp._next)
                {
                to.resetPtr(ptrc);
                if ((i = (int)relinkp.obj._encodesize(to, mode)) < 0)
                    {
                    for (sub = obj._sub; sub != null && sub != relinkp.obj;
                        sub = sub._next, map_num++);
                    _multi_stuff(map_num, obj);
                    return (i - size);
                    }
                ptrc += i;
                size += i;
                }
            }
        else for (sub = obj._sub; sub!=null; sub=sub._next, map_num++)
            {
            if ((of != 0) && (sub._next == null)) break;
            to.resetPtr(ptrc);
            i = (int)sub._encodesize(to, mode);
            if (i < 0)
                {
                _multi_stuff(map_num, obj);
                return i - size;
                }
            ptrc += i;
            size += i;
            }
        return size;
        } 

    protected int _remove()
    {
        int index;
        if ((_supra == null) || ((_supra._flags & AsnStatic.ASN_OF_FLAG)==0))
            return asn_obj_err(AsnStatic.ASN_NOT_OF_ERR);
        if (_supra._sub == this)
        {
            index=0;
            if (_next==null)
                return asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
            _supra._sub = _next;
            if (_next._next == null)
            {
                _supra._flags &= ~(AsnStatic.ASN_FILLED_FLAG);
                _supra._fill_upward(0);
            }
        }
        else
        {
            AsnObj prev;
            for (index=1, prev=_supra._sub; (prev._next!=null) && (prev._next!=this);
                prev=prev._next, index++);
            prev._next = _next;
        }
        _next=null;
        _supra=null;
        return index;
    }

    protected void _setup(AsnObj prev, AsnObj curr, short flags, int tag)
    {
        curr._supra = this;
        if (prev != null)
            prev._next = curr;
        else
            _sub = curr;
        curr._flags |= flags;
        if (tag != 0)
            curr._set_type_tag(tag);
    }

    protected int _set_asn_lth(AsnByteArray array, int from, int to, int mode)
        {
        //to points to one after the end of the from array
        int lth, tmp;
        int count;
        int end;

        int start = array.getPtr(); // save
        if ((array.index(from++) & AsnStatic.ASN_XT_TAG) == 
            AsnStatic.ASN_XT_TAG)
            {
            while ((array.index(from) & AsnStatic.ASN_INDEF) != 0) from++;
	    from++;
            }
        int bwd = (int)(array.index(from++));
        if ((bwd & AsnStatic.ASN_INDEF) != 0)
            {
            bwd &= ~AsnStatic.ASN_INDEF;
            if ((mode & AsnStatic.ASN_READING) != 0)
                for (count = from, end = count + bwd; end < to;
                    array.setByte(array.index(end++), count++));
            to -= bwd;
            }
        else bwd = 0;
	lth = to - from;
        if (lth >= 128 && ((mode & AsnStatic.ASN_READING) != 0))
            {
            for (count = to, tmp = lth; tmp != 0; tmp >>= 8, to++);
              while (count > from) array.setByte(array.index(--count), --to);
            }
        count = _encode_lth(array, --from, lth) - 1 - bwd;
        array.resetPtr(start + count);
        return count;
        }

    protected AsnObj _set_pointers(AsnObj asnObj)
    {
        /**Function: Fills in pointers etc. for duplicated object**/
        asnObj._flags |= _flags | AsnStatic.ASN_DUPED_FLAG;
        asnObj._flags &= ~(AsnStatic.ASN_FILLED_FLAG);
        asnObj._tag   = _tag;
        asnObj._type  = _type;
        asnObj._supra = _supra;    /* If this is a defined-by, flag the chosen one */
        if (_type == AsnStatic.ASN_CHOICE &&
            ((_flags & AsnStatic.ASN_DEFINED_FLAG)!=0))
        {
            AsnObj sub, tobj;
            for (sub = _sub, tobj = asnObj._sub;(sub!=null) && (tobj!=null) &&
                ((sub._flags & AsnStatic.ASN_CHOSEN_FLAG)==0);
                 sub = sub._next, tobj = tobj._next);    //end of for
            if ((sub!=null) && (tobj!=null))
                tobj._flags |= AsnStatic.ASN_CHOSEN_FLAG;
        }
        return asnObj;
    }

    protected void _set_sub_flag(AsnObj objp, short flag)
    {
        objp._flags |= flag;
    }

    protected void _set_tag(AsnObj tobj, int tag)
    {
        tobj._tag = tag;
    }

    protected void _set_type_tag(int tag)
    {
        _tag = tag;
        if (_type == 0)
            _type = (short)tag;
    }

    protected void _set_supra(AsnObj asnObj)
    {
        if (asnObj != null)
        {
            asnObj._supra = this;
            asnObj._fill_upward((asnObj._flags & AsnStatic.ASN_FILLED_FLAG));
        }
    }

    private AsnObj _tag_match(int tag, int[] map_buf, int map_index)
    {
        //called only by _tag_scan
        AsnObj obj, tobj = null;
        obj = this;
        if ((_supra != null) && (_supra._type == AsnStatic.ASN_SET) &&
            ((_supra._flags & AsnStatic.ASN_OF_FLAG)==0))
        {
            AsnSet set = (AsnSet)(_supra);
            for (obj = _supra._sub; (obj != null); obj = obj._next)
	      {
		if (((obj._flags & AsnStatic.ASN_POINTER_FLAG) != 0) ||
		    obj._tag == AsnStatic.ASN_CHOICE)
		  tobj = obj._tag_search(tag, map_buf, 0);
		else tobj = obj;
		if ((tobj !=null) && tobj._tag == tag) break;
	      }
       /* objp is at current level; tobjp may be 'down' one or more levels */
	    if ((obj==null) ||
		((tobj != null) && ((tobj._flags & AsnStatic.ASN_FILLED_FLAG) != 0)))
	      return null;
        set.add_link(obj);
	obj = tobj;
        }
        else if (_tag == AsnStatic.ASN_CHOICE)
            return _tag_search(tag, map_buf, 0);
        else if (_type == AsnStatic.ASN_ANY)
            _tag = tag;
        else if ((_tag != tag) &&
		 ((_tag != (tag & ~(AsnStatic.ASN_CONSTRUCTED))) ||
		  (_type >= AsnStatic.ASN_SEQUENCE)))
            obj = null;
        return obj;
    }

    protected AsnObj _tag_scan(AsnObjRef objref, AsnByteArray str, int of, 
        int[] map_buf, int map_index)
        {
        //not quite finished
        int holder = str.getPtr();
        int tag = decode_asn_tag(str);
        int index;
        AsnObj tobj = objref.obj;

        if (of == 0)
            {
            //  *** double CHECK the logic here...
            for ( ; objref.obj != null && 
               (tobj = objref.obj._tag_match(tag, map_buf, map_index)) == null &&
               (objref.obj._flags & AsnStatic.ASN_OPTIONAL_FLAG) != 0; 
               objref.obj = objref.obj._next, map_buf[map_index]++);
            }
        else
            {
            if ((tobj._next == null) || ((tobj._flags & AsnStatic.ASN_FILLED_FLAG)!=0))
                {
                index = ((AsnArray)tobj).insert();
                if (index >= 0)
                    {
                    AsnArray array = (AsnArray)(tobj._supra._sub);
                    objref.obj = tobj = array._index_op(index);
                    }
                else tobj = null;
                }
            if (tobj._type == AsnStatic.ASN_CHOICE)
                tobj = tobj._tag_search(tag, map_buf, 0);
            }
        if (tobj != null)
        {
            if (tobj._type == AsnStatic.ASN_ANY) {
              tobj._tag = tag;
              if ((of !=0) && (tobj._next !=null) && (tobj._next._next == null))
              tobj._next._tag = tag;
            }
            if ((tobj._tag != tag) &&
               (tobj._tag  != (tag & ~(AsnStatic.ASN_CONSTRUCTED)) ||
                (tobj._type >= AsnStatic.ASN_SEQUENCE))) {
                tobj = null;
             }
        }
        str.resetPtr(holder);
        return tobj;
    }

    protected AsnObj _tag_search(int tag, int[] map_buf, int map_index)
    {
        AsnObj obj = this;
        AsnObj tobj = this;
        AsnObj sub;

	map_index++;
        do
            {
            obj = tobj;
	    if ((obj._flags & AsnStatic.ASN_POINTER_FLAG) == 0)
		{
                if ((obj._flags & AsnStatic.ASN_DEFINED_FLAG)!=0)
                    {
                    for (tobj = obj._sub, map_buf[map_index] = 0,
                        map_buf[map_index + 1] = -1; 
                        (tobj != null) && 
                        ((tobj._flags & AsnStatic.ASN_CHOSEN_FLAG) == 0); 
                        tobj = tobj._next, map_buf[map_index]++);
                    map_index++;
                    }
                if (tobj == null) asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
                else if ((tobj == obj) || (tobj._tag == AsnStatic.ASN_CHOICE))
                    {
                    for (tobj = tobj._sub, map_buf[map_index] = 0,
                        map_buf[map_index + 1] = -1;
                        tobj != null && tobj._tag != tag && 
                        tobj._type != AsnStatic.ASN_ANY;
                        tobj = tobj._next, map_index++)
                        {
                        if ((((tobj._type == AsnStatic.ASN_CHOICE) && 
                            (tobj._type == tobj._tag)) ||
                            ((obj._flags & AsnStatic.ASN_POINTER_FLAG) != 0)) &&
                            ((sub = tobj._tag_search(tag, map_buf, map_index)) 
                            != null))
                            {
                            tobj = sub;
                            break;
                            }
                        }
                     map_index++;
                    }
                }
	    else    // pointer object
		{
		if (tag == obj._tag || obj._type == AsnStatic.ASN_CHOICE)
		    {
		    if (obj._sub == null) ((AsnRef)obj).add();
		    else obj._sub.clear();
		    obj._sub._tag = tobj._tag;
		    }
		else if (obj._sub != null) obj._sub = null;
		tobj = obj._sub;
		}
	    }
        while((tobj != null) && ((tobj._tag == AsnStatic.ASN_CHOICE) ||
            ((tobj._flags & AsnStatic.ASN_POINTER_FLAG) != 0)));
        map_buf[map_index + 1] = -1;
        return tobj;

    }

    protected int _write(AsnByteArray from, int lth)
    {
        int holder = from.getPtr();
        int ptrc = holder;
        int end = holder + (int)lth;
        int i;
        AsnObj obj, sub, superp, tobj;
        obj = this;

        //step 1
        i = obj._check_of();
        if (i < 0) return i;
        if ((_type == AsnStatic.ASN_NONE) ||
            ((_type == AsnStatic.ASN_NULL) && (lth > 0)))
            return asn_obj_err((_type == AsnStatic.ASN_NONE) ?
                AsnStatic.ASN_NONE_ERR : AsnStatic.ASN_TYPE_ERR);
        if (obj._type == AsnStatic.ASN_CHOICE)
        {
            if ((((_flags & AsnStatic.ASN_DEFINED_FLAG)!=0) &&
		 ((obj = _check_defined())==null)) ||
		((_supra != null) &&
		 ((_supra._flags & AsnStatic.ASN_DEFINED_FLAG)!=0) &&
		 (obj = _supra._check_defined()) != this))
                return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
            if (obj._type == AsnStatic.ASN_CHOICE)
            {
                if ((obj._sub._type >= mask_table.length) ||
                    (mask_table[obj._sub._type]==0))
                    return asn_obj_err(AsnStatic.ASN_CHOICE_ERR);
                for (i = 0xFF; ptrc < end; i &= (char_table[from.index(ptrc++)]));
                for (tobj = obj._sub; (tobj!=null) && (tobj._type < mask_table.length)
                    && ((mask_table[tobj._type] & i)==0); tobj = tobj._next);
                if ((ptrc < end) || (tobj == null))
                {
                    asn_obj_err(AsnStatic.ASN_NO_CHOICE_ERR);
                    return -1;
                }
                for (sub = obj._sub; sub != null; sub.clear(), sub = sub._next);
                obj = tobj;
            }
        }

        // Step 1a
	sub = obj;
        for (superp = sub._supra; superp != null; superp = (sub = superp)._supra)
        {
            if ((superp._type == AsnStatic.ASN_CHOICE) &&
                ((superp._flags & AsnStatic.ASN_DEFINED_FLAG)!=0))
            {
                for (tobj = superp._sub; (tobj!=null) &&
                    ((tobj._flags & AsnStatic.ASN_CHOSEN_FLAG)==0); tobj = tobj._next);
                if (tobj != sub) return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
            }
        }

        // Step 2
        int table_index=0;
        if (((obj._type & AsnStatic.ASN_CONSTRUCTED)==0) ||
	    (obj._sub == null) || lth == 0)
        {
            if ((obj._type == AsnStatic.ASN_BOOLEAN) && (lth != 1))
                return asn_obj_err(AsnStatic.ASN_BOUNDS_ERR);
            if ((obj._type < mask_table.length) && (mask_table[obj._type]!=0) &&
                ((i = obj._check_mask(from,lth))<=0)) return i;
            if ((obj._max != 0) && ((obj._csize(from,lth) > obj._max) ||
                (obj._csize(from,lth) < obj._min))) return asn_obj_err(AsnStatic.ASN_BOUNDS_ERR);
            if ((obj._flags & AsnStatic.ASN_TABLE_FLAG) != 0)
            {

                for (table_index = 0, sub = obj._sub;
                    (sub!=null) && (sub._compare(from,lth) != 0);
                    sub = sub._next, table_index++);
                if (sub == null) return asn_obj_err(AsnStatic.ASN_DEFINER_ERR);
            }
            if (obj._type == AsnStatic.ASN_INTEGER)
            {
                while ((lth > 1)
		       && (((from.index()==0) &&
			    ((from.index(ptrc + 1) & 0x80)==0)) ||
			   ((from.index()==0xFF) &&
			    ((from.index(ptrc + 1) & 0x80)!=0))))
                {
                    from.incrPtr();
                    ptrc = from.getPtr();
                    lth--;
                }
            }
            if ((obj._flags & AsnStatic.ASN_ENUM_FLAG) != 0)
            {
                superp = obj._supra;
                if (superp._type == AsnStatic.ASN_BITSTRING)
                {
		    AsnIntRef shift = new AsnIntRef();
                    int j;
                    int newsize = ((obj._tag  + 8) >> 3) + 1;
                    if (superp._valp == null)
                        superp._valp = new AsnByteArray(newsize);
                    else if (((j = superp._valp.index(0)) != 0) ||
                        (newsize > superp._valp.getLength()))
                        {
                        i = ((AsnBitString)superp).vsize();
                        AsnByteArray tmpc = new AsnByteArray((newsize > i) ? newsize: i);
                        i = ((AsnBitString)superp).read(tmpc, shift);
                        ((AsnBitString)superp).write(tmpc, newsize - 1,
                            shift.val);
                        tmpc = null;
                        }
                    for (j = (obj._tag & 7), i = 0x80; j-- != 0; i >>= 1);
                    j = 1 + (obj._tag >> 3 );
                    if (from.index()!=0)
                        superp._valp.setByte((byte) (superp._valp.index(j) | i) , j);
                    else superp._valp.setByte((byte) (superp._valp.index(j) & ~i) , j);
                }
                else if ((superp._type == AsnStatic.ASN_INTEGER) ||
                    (superp._type == AsnStatic.ASN_ENUMERATED)) return superp.write(obj._tag);
                else return asn_obj_err(AsnStatic.ASN_GEN_ERR);
            }
            else if  ((obj._type & AsnStatic.ASN_CONSTRUCTED) ==0 || obj._sub == null)
            {
              if (obj._valp != null) {
                obj._valp = null;
                }
                AsnByteArray temparray = from.subArray(from.getPtr(),lth);
                obj._valp = new AsnByteArray(temparray);
            }
            obj._flags |= AsnStatic.ASN_FILLED_FLAG;
            AsnIntRef tmp = new AsnIntRef(0);
            if ((obj._type == AsnStatic.ASN_UTCTIME || obj._type == AsnStatic.ASN_GENTIME)
                && (((AsnTime)obj).read(tmp) < 0))
                return -1;

            //Step 3
            obj._fill_upward(AsnStatic.ASN_FILLED_FLAG);
            sub = obj;
            // Step 4
            if (((obj._flags & AsnStatic.ASN_TABLE_FLAG)!=0) &&
                ((AsnTableObj)obj)._set_definees(table_index) < 0)
	      return -1;
	    from.resetPtr(holder);
            return lth;
        }
        // Step 5
        int of = (obj._flags & AsnStatic.ASN_OF_FLAG);
        obj.clear();
        if ((of!=0) && (lth==0) && (obj._min==0))
            obj._fill_upward(AsnStatic.ASN_FILLED_FLAG);
        int map_num;
	int hold1;
        for (map_num = 0, hold1 = from.getPtr(), sub = obj._sub;
            (sub != null || of != 0) && hold1 < end; sub = sub._next, map_num++)
        {
            from.resetPtr(hold1);
            i = sub.decode(from);
            from.resetPtr(hold1);
            if (of == 0)      /* in case decode skipped some empty optional items */
                for ( ; (sub._next != null) && ((sub._flags & AsnStatic.ASN_FILLED_FLAG)==0);
                    sub = sub._next, map_num++);
            else     /* because decode inserted the object ahead of sub */
                for (tobj = sub, sub = obj._sub, map_num = 0; (sub != tobj) &&
                    (sub._next != tobj); sub = sub._next, map_num++);
            if (i < 0)
            {
                stuff(map_num);
		from.resetPtr(holder);
                return (i - (hold1 - ptrc));
            }
            hold1 += i;
        }
	from.resetPtr(holder);
        return (hold1 - ptrc);
    }


    private static int get_num(AsnByteArray str, int lth)
        {
        int val=0;
        for (int i = str.getPtr(); lth-- != 0; i++)
            {
            val = (val*10) + str.index(i) - '0';
            }
        return val;
        }

    private static int put_num (AsnByteArray to, int val, int lth)
    {
        int holder = to.getPtr();
        int count = holder + lth;
        while (count > holder)
        {
            to.setByte((byte)((val % 10) + '0'), --count);
            val /= 10;
        }
        return val;
    }

    private int decode_asn_tag(AsnByteArray str)
    {
        int typ = 0;
        int counter = str.getPtr();
        int temp;

        if ((str.index(counter) & AsnStatic.ASN_XT_TAG) == AsnStatic.ASN_XT_TAG)
            {
            for (counter++; (str.index(counter) & AsnStatic.ASN_INDEF_LTH)!=0; counter++);
            temp = counter+1;
            for ( ; counter>=str.getPtr();
                typ = (typ <<= 8) + (((int)str.index(counter--)) & 0xFF));
            str.incrPtr(temp-str.getPtr());
            }
        else
            {
            typ = ((int)str.index(counter++)) & 0xFF;
            str.incrPtr(counter-str.getPtr());
            }
        return typ;
    }

    private int decode_asn_lth(AsnByteArray str)
        {
        byte lth = 0;
        int counter = str.getPtr();
        int ansr = 0;

        if (((lth = str.index(counter++)) & AsnStatic.ASN_INDEF_LTH) != 0)
            {
            lth &= ~AsnStatic.ASN_INDEF_LTH;
            if (lth != 0)
                {
                for (ansr = 0; lth-- != 0; ansr = (ansr << 8) + (str.index(counter++) & 0xFF));
                }
            }
	else ansr = lth;
        str.incrPtr(counter - str.getPtr());
        return ansr;
        }

    private void buf_stuff(int[] map_buf)  
    {
        int i;
	for (i = 0; map_buf[i] >= 0; i++);
	for (i--; i >= 0; stuff(map_buf[i--]));
        System.out.println("Stuff type " + this._type + " tag " + this._tag + " map_string " +
             error.asn_map_string);
    }

    private void stuff(int map_num)
        {
        char buf[] = new char[12];
        int count;
        int tmp, lth;

        map_num++;     /* one-based */
	error.asn_map_string = map_num + "." + error.asn_map_string;
        }

    public void print()
      {
      _valp.print();
      }
}

class TagTable
{
    long tag;
    int lth;
    AsnObj obj;
    int orig;

    public TagTable()
    {
        tag = 0;
	lth = 0;
        obj = null;
        orig = 0;
    }
}
