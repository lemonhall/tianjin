gcc -g -Wall -O0 -lpcap test.c -o tcphijack `pkg-config --cflags --libs glib-2.0`
