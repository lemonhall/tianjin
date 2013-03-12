
1、依赖
yum install libpcap-devel libpcap

2、编译
gcc -lpcap test.c
具体见build.sh

3、运行
./a.out eth0
具体见run.sh
另外，应该可以探测操作系统本身的能力

4、TODO：
a）抓包已经很OK了，接下来是过滤出/特定域名/根目录本身
b) 搞定了发包的顺序问题，要引用libc.h的g_ntohl()比较安全.....
