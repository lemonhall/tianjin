
1、依赖
yum install libpcap-devel libpcap

2、编译
gcc -lpcap test.c

3、运行
./a.out eth0

4、TODO：
a）抓包已经很OK了，接下来是过滤出/特定域名/根目录本身