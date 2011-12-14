AUTOMAKE_OPTIONS = 1.6 foreign

TESTS = ./runRTRTest.sh

check_SCRIPTS = runRTRTest.sh
check_DATA = \
	root.cer \
	as-1.roa \
	as-2.roa \
	as-3.roa \
	as-4.roa \
	as-5.roa \
	as-6.roa

%.key:
	../../cg/tools/gen_key "$@" 1024

root.cer: root.key
	cd ../../testbed/src && ./create_object CERT \
		-f ../../subsystemTests/rtr/root.options \
		outputfilename=../../subsystemTests/rtr/"$@" \
		subjkeyfile=../../subsystemTests/rtr/"$<"

as-%.ee.cer: ee.key root.key root.cer
	IP4=""; IP6=""; \
	for IP_OCTET in `seq 1 "$*"`; do \
		IP4="$$IP4,`printf '%u.%u.0.0/16' '$*' $$IP_OCTET`,`printf '%u.0.%u.0/24' '$*' $$IP_OCTET`"; \
		IP6="$$IP6,`printf '%x::%x00/120' '$*' $$IP_OCTET`,`printf '%x:%x::/32' '$*' $$IP_OCTET`"; \
	done; \
	IP4=`echo "$$IP4" | cut -c 2-`; \
	IP6=`echo "$$IP6" | cut -c 2-`; \
	cd ../../testbed/src && ./create_object CERT \
		-f ../../subsystemTests/rtr/ee.options \
		outputfilename=../../subsystemTests/rtr/"$@" \
		parentcertfile=../../subsystemTests/rtr/root.cer \
		parentkeyfile=../../subsystemTests/rtr/root.key \
		subjkeyfile=../../subsystemTests/rtr/"$<" \
		subject="as$*" \
		ipv4="$$IP4" \
		ipv6="$$IP6" \
		as="$*"

as-%.roa: as-%.ee.cer ee.key
	IP4=""; IP6=""; \
	for IP_OCTET in `seq 1 "$*"`; do \
		IP4="$$IP4,`printf '%u.%u.0.0/16' '$*' $$IP_OCTET`,`printf '%u.0.%u.0/24%%25' '$*' $$IP_OCTET`"; \
		IP6="$$IP6,`printf '%x::%x00/120' '$*' $$IP_OCTET`,`printf '%x:%x::/32%%127' '$*' $$IP_OCTET`"; \
	done; \
	IP4=`echo "$$IP4" | cut -c 2-`; \
	IP6=`echo "$$IP6" | cut -c 2-`; \
	cd ../../testbed/src && ./create_object ROA \
		outputfilename=../../subsystemTests/rtr/"$@" \
		eecertlocation=../../subsystemTests/rtr/"$<" \
		eekeylocation=../../subsystemTests/rtr/ee.key \
		asid="$*" \
		roaipv4="$$IP4" \
		roaipv6="$$IP6"

EXTRA_DIST = \
	*.options \
	badPDUs.py \
	*.correct

CLEANFILES = *.log *.diff *.key *.cer *.roa
