# Run the below command to generate the TAGS file, then run this script with TAGS as stdin to see duplicate function names
#
# find . -name \*.c -not -path ./deprecated/\* -print0 | xargs -0 etags --declarations -D --no-globals -I --no-members

import collections
import sys

src_file = None
got_section_header = 0

# function name => list of files
functions = collections.defaultdict(lambda: set())


for line in sys.stdin:
    line = line.rstrip('\r\n')
    if got_section_header == 0:
        if line != "\x0c":
            exit("invalid header first line: %s" % line)
        got_section_header = 1
    elif got_section_header == 1:
        src_file, sep, tail = line.rpartition(',')
        if sep != ',':
            exit("invalid header second line: %s" % line)
        got_section_header = 2
    elif got_section_header == 2:
        if line == "\x0c":
            got_section_header = 1
        else:
            definition, sep, tail = line.rpartition('\x7f')
            if sep != '\x7f':
                exit("invalid definition line: %s" % line)
            if definition[-1] == '(':
                head, sep, function = definition.rpartition(' ')
                if sep != ' ':
                    function = sep
                function = function.rstrip('(')
                function = function.lstrip('*')
                functions[function].add(src_file)
    else:
        exit("unexpected value for got_section_header, %s" % got_section_header);


for k, v in functions.iteritems():
    if len(v) > 1:
        print k, len(v), ' '.join(v)
