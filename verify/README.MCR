The verification code is modified slightly to use the filename
in determining the parent.  We have the following hierarchy:

0.cer.pem	SS CA TA cert
1.cer.pem	CA cert, child of 0.cer.pem
2.cer.pem	CA cert, child of 1.cer.pem
3.cer.pem	EE cert, child of 2.cer.pem
4.cer.pem	random CA cert, not a child of any other

So 0-3 should verify and 4 should not.


