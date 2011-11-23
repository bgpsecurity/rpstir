BEGIN {
	IN_BLOCK = 0;

	PRE_LINE = "^[ \t]*";
	POST_LINE = "[ \t]*$";

	# tmp variables
	X = "((\\*|#( *\\*)?) *)?";
	PRE_BLOCK = "(/\\* *|# *(/\\* *)?)?";
	POST_BLOCK = " *(\\*/)?";

	BLOCK[ 0] = PRE_BLOCK "\\*\\*\\*\\*\\* BEGIN LICENSE BLOCK \\*\\*\\*\\*\\*";
	BLOCK[ 1] = X;
	BLOCK[ 2] = X "BBN Address and AS Number PKI Database/repository software";
	BLOCK[ 3] = X "Version [^ ]*";
	BLOCK[ 4] = X;
	BLOCK[ 5] = X "US government users are permitted unrestricted rights as";
	BLOCK[ 6] = X "defined in the FAR.";
	BLOCK[ 7] = X;
	BLOCK[ 8] = X "This software is distributed on an \"AS IS\" basis, WITHOUT";
	BLOCK[ 9] = X "WARRANTY OF ANY KIND, either express or implied.";
	BLOCK[10] = X;
	BLOCK[11] = X "Copyright .*";
	BLOCK[12] = X;
	BLOCK[13] = X "Contributor(\\(s\\)|s)?: .*";
	BLOCK[14] = X;
	BLOCK[15] = X "\\*\\*\\*\\*\\* END LICENSE BLOCK \\*\\*\\*\\*\\*" POST_BLOCK;

	BLOCK_END = 15;
}

{
	if (!IN_BLOCK) {
		if ($0 ~ PRE_LINE BLOCK[0] POST_LINE) {
			IN_BLOCK = 1;
			BLOCK_LINENO = 0;
			SAVED_BLOCK = $0;
			print "Matched line " BLOCK_LINENO >> "/dev/stderr";
		} else {
			print;
		}
	} else {
		if ($0 ~ PRE_LINE BLOCK[BLOCK_LINENO + 1] POST_LINE) {
			SAVED_BLOCK = SAVED_BLOCK RS $0;
			BLOCK_LINENO += 1;
			print "Matched line " BLOCK_LINENO >> "/dev/stderr";
			if (BLOCK_LINENO == BLOCK_END) {
				IN_BLOCK = 0;
			}
		} else {
			print SAVED_BLOCK;
			print;
			IN_BLOCK = 0;
		}
	}
}

END {
	if (IN_BLOCK) {
		print SAVED_BLOCK;
	}
}
