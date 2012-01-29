#! /usr/bin/env python
''' Generate a series of pretend rsync URIs.
Domain name strings are generated like so:  a, b, ..., z, aa, ab, ...
Path strings are taken from the head of the list of domain name strings.
The number of URIs produced is domains * paths * tails.'''

from random import shuffle
import sys


tails = [
        "VdpdC337jcPzlzs6fUzRPvLK6b4.crl",
        "vfN0k0OCj0FOB2b-VgzDTukk0Rk.mnf",
        "u1vXW6wIOWm8vdYlXVSQrwBNhdY.roa",
        "j-yin7SQr-c2TjFmqpm6qFAnY40.roa",
        "U5-_NOSsK-f2gyNhCH-MB89HTK8.roa",
        "-4M9zf384Gy-2OVCtJEg81l3-Qo.roa",
        "UcoK1YBvzCdGeHxuEH4xr8SufTE.roa",
        "ueL0ZxFBQfHaf1MBgx5qL76ygvI.roa",
        "2Ij6sPeArvjzMRZKGlGknDj2RWo.roa",
        "UGEpusWGdZOZ7vRrwQoEBwMmBLg.roa",
        "FwhJ78He79TLSXFvve-6Jgw8b_M.roa",
        "UNQwmKywgGtxNTXILlQEFwgy2LM.roa",
        "jjDzBZfKORBrQyX3LuHdeMdvlWI.roa",
        "uRlzhelrL1iorFWqNfL-6Uk6FXI.roa",
        ""]


def increment(input_string):
    n = len(input_string) - 1
    string_as_list = []
    for ch in input_string:
        string_as_list.append(ch)

    while n >= 0:
        if 'z' != string_as_list[n]:
            string_as_list[n] = chr(ord(string_as_list[n]) + 1)
            break;
        else:
            string_as_list[n] = 'a'
            if n == 0:
                string_as_list = ['a'] + string_as_list
                break
            else:
                n -= 1

    output_string = ""
    for ch in string_as_list:
        output_string += ch

    return output_string


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "need args"
        exit()

    num_domains = int(sys.argv[1])
    filename = sys.argv[2]

    if num_domains >= 10:
        num_paths_per_domain = 10
    else:
        num_paths_per_domain = num_domains

    i = 1
    domains = ["a"]
    while i < num_domains:
        next_val = increment(domains[len(domains) - 1])
        domains.append(next_val)
        i += 1
    shuffle(domains)

    f = open(filename, 'w')
    paths = domains[:num_paths_per_domain]
    for i in range(num_domains):
        shuffle(paths)
        for j in range(len(paths)):
            shuffle(tails)
            for k in range(len(tails)):
                f.write("DIR=rsync://"+domains[i]+".com/somepath/"+domains[j]+"/"+tails[k]+'\n')
    f.close()

