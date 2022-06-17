icmp6filter_pym.so: icmp6filter_pym.c
	gcc -fPIC -shared icmp6filter_pym.c -O2 -o icmp6filter_pym.so
