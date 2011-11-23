BEGIN {
	IN_BLOCK = 0;

	PRE_LINE = "^[ \t]*";
	POST_LINE = "[ \t]*$";

	# tmp variables
	X = "((\\*|#( *\\*)?) *)?";
	PRE_BLOCK = "(/\\* *|# *(/\\* *)?)?";
	POST_BLOCK = " *(\\*/)?";

	BLOCK_END = 0;

	BLOCK[BLOCK_END++] = PRE_BLOCK "\\*\\*\\*\\*\\* BEGIN LICENSE BLOCK \\*\\*\\*\\*\\*";
	BLOCK[BLOCK_END++] = X;
	BLOCK[BLOCK_END++] = X "BBN Address and AS Number PKI Database/repository software";
	BLOCK[BLOCK_END++] = X "Version [^ ]*";
	BLOCK[BLOCK_END++] = X;
	BLOCK[BLOCK_END++] = X "US government users are permitted unrestricted rights as";
	BLOCK[BLOCK_END++] = X "defined in the FAR.";
	BLOCK[BLOCK_END++] = X;
	BLOCK[BLOCK_END++] = X "This software is distributed on an \"AS IS\" basis, WITHOUT";
	BLOCK[BLOCK_END++] = X "WARRANTY OF ANY KIND, either express or implied.";
	BLOCK[BLOCK_END++] = X;
	BLOCK[BLOCK_END++] = X "Copyright .*";
	BLOCK[BLOCK_END++] = X "All Rights Reserved.";
	BLOCK[BLOCK_END++] = X;
	BLOCK[BLOCK_END++] = X "Contributor(\\(s\\)|s)?: .*";
	BLOCK[BLOCK_END++] = X;
	BLOCK[BLOCK_END++] = X "\\*\\*\\*\\*\\* END LICENSE BLOCK \\*\\*\\*\\*\\*" POST_BLOCK;

	BLOCK_END--;
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
