#!/usr/bin/python

from netaddr import IPRange, IPNetwork, IPAddress
import sys

class ParseError(Exception):
    """Exception raised for errors in trying to parse IP addresses."""
    def __init__(self, msg="Unknown error"):
        self.msg = msg
    def __str__(self):
        return repr(self.msg)

def is_range_simple(s):
    """Simple check to differentiate range input from prefix input."""
    if s.find("-") != -1:
        return True
    else:
        return False

def is_prefix_simple(s):
    """Simple check to differentiate range input from prefix input."""
    if s.find("/") != -1:
        return True
    else:
        return False

def hexify_ipaddr_string(s):
    [first, last, version] = parse_ipaddr(s)
    return "%s %s" % (addr_hex_string(first, version),
                      addr_hex_string(last, version))
    
def parse_ipaddr(s):
    """Return [first, last, version], where first/last are the pair of
    long integers representing the first/last IP address of the range
    or prefix.  'version' is either 4 or 6, corresponding to IPv4 or
    IPv6."""
    if is_range_simple(s):
        pair = s.split("-")
        if len(pair) != 2:
            raise ParseError("Invalid range: %s" % s)
        pair[0] = pair[0].strip() # get rid of whitespace
        pair[1] = pair[1].strip() # get rid of whitespace
        x = IPRange(pair[0], pair[1])
        return [x.first, x.last, x.version]
    elif is_prefix_simple(s):
        x = IPNetwork(s.strip())
        return [x.first, x.last, x.version]
    else:
        x = IPAddress(s.strip())
        return [x.value, x.value, x.version]

def addr_hex_string(n, version):
    if version == 4:
        return "0x%8.8X" % n
    elif version == 6:
        return "0x%32.32X" % n
    else:
        raise ParseError("Invalid IP version: %d" % version)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: %s <ip prefix or range>" % sys.argv[0]
        sys.exit(-1)
        
    s = " ".join(sys.argv[1:])
    try:
        print hexify_ipaddr_string(s)
    except:
        print >>sys.stderr, "Error parsing string: " + s
        sys.exit(-2)
    sys.exit(0)
