import re
import sys

re_begin_line = re.compile("; <<>> DiG 9.8.5-P1 <<>> @(.*) \+dnssec (.*)")
re_flags = re.compile(";; flags: (.*); QUERY: [0-9]+, ANSWER: [0-9]+, AUTHORITY: [0-9]+, ADDITIONAL: [0-9]+")
re_status = re.compile(";; ->>HEADER<<- opcode: QUERY, status: ([A-Z]+), id: [0-9]+")
re_time = re.compile(";; Query time: ([0-9]+) msec")
re_date = re.compile(";; WHEN: (.+)")


if not (len(sys.argv) == 3):
    print "Syntax:"
    print "    python parse_dig.py <input-file> <output-file>"
    print "  input-file is raw dig output"
    print "  output-file is the name of the output file"

input_file = open(sys.argv[1], "r")
output_file = open(sys.argv[2], "w")

linenum = 0

domain = None
flags = None
status = None
time = None
date = None

for line in input_file:
    begin_result = re_begin_line.match(line)
    flags_result = re_flags.match(line)
    status_result = re_status.match(line)
    time_result = re_time.match(line)
    date_result = re_date.match(line)

    if begin_result is not None:
        domain = begin_result.group(2)

    if flags_result is not None:
        flags = flags_result.group(1)

    if status_result is not None:
        status = status_result.group(1)

    if time_result is not None:
        time = time_result.group(1)
        
    if date_result is not None:
        date = date_result.group(1)
        
        secure = "DNS"
        if "ad" in flags.split():
            secure = "DNSSEC"
        output_file.write (domain + ", " + secure + ", " + status + ", " + time + ", " + date + "\n")

input_file.close()
output_file.close()
