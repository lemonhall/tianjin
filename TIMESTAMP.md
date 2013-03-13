http://www.stearns.org/p0f/devel/p0f.c
使用Timestampe来做指纹识别什么的

  {
    void* opt_ptr;
    int opt;
    opt_ptr=(void*)tcph+sizeof(struct tcphdr);
    while (dupa<hlen) {
      opt=(int)(*(u_char*)(opt_ptr+dupa));
      dupa+=1;
      switch(opt) {
        case TCPOPT_EOL:
	  dupa=100000; break; // Abandon ship!
        case TCPOPT_NOP:
  	  nop=1;
	  break;
	case TCPOPT_SACKOK:
 	  sok=1;
	  dupa++;
	  break;
	// Long options....
	case TCPOPT_MAXSEG:
	  dupa++;
  	  mss=EXTRACT_16BITS(opt_ptr+dupa);
  	  dupa+=2;
	  break;
	case TCPOPT_WSCALE:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
  	  wscale=(int)*((u_char*)opt_ptr+dupa);
	  dupa+=olen;
	  break;
	case TCPOPT_TIMESTAMP:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
	  timestamp= *((u_int32_t*)((void*)opt_ptr+dupa));
	  dupa+=olen;
	  break;
	default:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
	  dupa+=olen;
	 break;
      }
    }
  }

=========================================================

1、第一步
========
==>
GET / HTTP 1.0

Timestamp value      : 691563071
Timestamp echo replay: 524301471

2、第二步
========
<==
ACK空包

Timestamp value      : 524301494
Timestamp echo replay: 691563071

3、第三步
========
<==
ACK,PSH内容包...

Timestamp value      : 524301495
Timestamp echo replay: 691563071


4、第四步
========
<==
ACK,PSH内容包（2）Segment了...

Timestamp value      : 524301495
Timestamp echo replay: 691563071

值是一样的....

5、第五步
========
<==
ACK,FIN包....

Timestamp value      : 524301495
Timestamp echo replay: 691563071