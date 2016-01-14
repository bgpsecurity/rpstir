#define MSP 1

#ifdef MSP
#define uchar unsigned char
#define ushort unsigned short
#define ulong unsigned long
#endif


/*
 * $i1(q( byte_cmp (s1,s2,lth) $i1)q)
 */
int byte_cmp(
    s1,
    s2,
    lth)
     uchar *s1,
     *s2;
     int lth;
{
    /*
     * Function: Compares lth bytes in strings s1 and s2
     *
     * Returns; 0 if they match; -1 if they don't
     */
    while (*s1++ == *s2++ && lth)
        lth--;
    return ((lth) ? -1 : 0);
}


/*
 * $i1(q( copynbytes (to,from,lth) $i1)q)
 */
int copynbytes(
    uchar * to,
    uchar * from,
    int lth)
{
    uchar *e;
    for (e = &from[lth]; from < e; *to++ = *from++);
    return lth;
}


/*
 * $i1(q( isempty (from,size) $i1)q)
 */
int isempty(
    uchar * from,
    int size)
{
    register uchar *b,
       *c;
    if (*from && *from != 0xFF)
        return 0;
    for (b = from, c = &b[size]; b < c && *b == *from; b++);
    return (b >= c);
}


/*
 * $i1(q( putx (c,val) $i1)q)
 */
uchar *putx(
    c,
    val)
     uchar *c;
     ulong val;
{
    uchar tmp = val & 0xF;
    if (val >>= 4)
        c = putx(c, val);
    if (tmp > 9)
        tmp += 7;
    *c++ = tmp + '0';
    return c;
}
