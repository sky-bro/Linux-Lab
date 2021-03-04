## 数据包监控程序

### 演示 Demo

* youtube: sniffer w/ raw socket - demo: [youtube](https://youtu.be/2liXzaIIyuE), [bilibili](https://www.bilibili.com/video/BV1jK4y1D77C/)

### 编译&运行

```shell
g++ main.cpp -o main # 编译
./main --help # 查看帮助
sudo ./main -aed # 运行示例 (需要root权限)
```

### 底层模块

- [x] 数据包的捕获过程

### 中层模块：协议分析模块

- [x] MAC层处理

- [x] ARP

  ```shell
  *************************ARP Packet******************************
  Ethernet Header
  	|-Source Address	    : 58-69-6C-A5-E2-D3
  	|-Destination Address	: FF-FF-FF-FF-FF-FF
  	|-Protocol		        : 0608
  
  ARP Header
  	|-Format of Hardware Address    : 1
  	|-Format of Protocol Address    : 2048
  	|-Lengh of Hardware Address     : 6
  	|-Lengh of Protocol Address     : 4
  	|-Opcode                        : 1
  
  Dump
    FF FF FF FF FF FF 58 69 6C A5 E2 D3 08 06 00 01 ......Xil.......
    08 00 06 04 00 01 58 69 6C A5 E2 D3 AC 14 00 01 ......Xil.......
    00 00 00 00 00 00 AC 14 00 01 00 55 59 DD 89 80 ...........UY..�
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
  *****************************************************************
  ```

- [x] IP层处理

- [x] TCP处理模块

  ```shell
  *************************TCP Packet******************************
  Ethernet Header
  	|-Source Address	    : 58-69-6C-A5-E2-D3
  	|-Destination Address	: C8-FF-28-3D-71-FD
  	|-Protocol		        : 0008
  
  IP Header
  	|-Version                 : 4
  	|-Internet Header Length  : 5 DWORDS or 20 Bytes
  	|-Type Of Service         : 0
  	|-Total Length            : 40  Bytes
  	|-Identification          : 7781
  	|-Time To Live            : 48
  	|-Protocol                : 6
  	|-Header Checksum         : 5154
  	|-Source IP               : 117.18.232.200
  	|-Destination IP          : 172.20.78.90
  
  TCP Header
  	|-Source Port          : 443
  	|-Destination Port     : 33220
  	|-Sequence Number      : 1652715440
  	|-Acknowledge Number   : 308764423
  	|-Header Length        : 5 DWORDS or 20 BYTES
  	|----------Flags-----------
  		|-Urgent Flag          : 0
  		|-Acknowledgement Flag : 1
  		|-Push Flag            : 0
  		|-Reset Flag           : 0
  		|-Synchronise Flag     : 0
  		|-Finish Flag          : 0
  	|-Window size          : 286
  	|-Checksum             : 36684
  	|-Urgent Pointer       : 0
  
  Dump
    C8 FF 28 3D 71 FD 58 69 6C A5 E2 D3 08 00 45 00 ..(=q.Xil.....E.
    00 28 1E 65 00 00 30 06 14 22 75 12 E8 C8 AC 14 .(.e..0.."u.....
    4E 5A 01 BB 81 C4 62 82 6F B0 12 67 5F 07 50 10 NZ....b.o..g_.P.
    01 1E 8F 4C 00 00 00 00 00 00 00 00             ...L........
  *****************************************************************
  ```

- [x] UDP处理模块

  ```shell
  *************************UDP Packet******************************
  Ethernet Header
  	|-Source Address	    : 58-69-6C-A5-E2-D3
  	|-Destination Address	: C8-FF-28-3D-71-FD
  	|-Protocol		        : 0008
  
  IP Header
  	|-Version                 : 4
  	|-Internet Header Length  : 5 DWORDS or 20 Bytes
  	|-Type Of Service         : 0
  	|-Total Length            : 1378  Bytes
  	|-Identification          : 0
  	|-Time To Live            : 44
  	|-Protocol                : 17
  	|-Header Checksum         : 20754
  	|-Source IP               : 203.208.50.58
  	|-Destination IP          : 172.20.78.90
  
  UDP Header
  	|-Source Port    	: 443
  	|-Destination Port	: 38665
  	|-UDP Length      	: 1358
  	|-UDP Checksum   	: 60224
  
  Dump
    C8 FF 28 3D 71 FD 58 69 6C A5 E2 D3 08 00 45 00 ..(=q.Xil.....E.
    05 62 00 00 40 00 2C 11 51 12 CB D0 32 3A AC 14 .b..@.,.Q...2:..
    4E 5A 01 BB 97 09 05 4E EB 40 D3 51 30 34 36 05 NZ.....N.@.Q046.
    CE 09 5D 06 A5 73 84 39 00 00 00 01 3A C4 0B 4F ..]..s.9....:..O
    89 E7 34 7D AB A5 0A DE 9F 13 D5 7E E9 18 59 27 ..4}.......~..Y'
    E3 EC 43 B1 0C FB 60 53 BD C5 AC 62 86 70 96 93 ..C...`S...b.p..
  ```

- [x] ICMP处理模块

  ```shell
  *************************ICMP Packet******************************
  Ethernet Header
  	|-Source Address	    : 00-00-00-00-00-00
  	|-Destination Address	: 00-00-00-00-00-00
  	|-Protocol		        : 0008
  
  IP Header
  	|-Version                 : 4
  	|-Internet Header Length  : 5 DWORDS or 20 Bytes
  	|-Type Of Service         : 0
  	|-Total Length            : 84  Bytes
  	|-Identification          : 3342
  	|-Time To Live            : 64
  	|-Protocol                : 1
  	|-Header Checksum         : 14526
  	|-Source IP               : 172.20.78.90
  	|-Destination IP          : 172.20.78.90
  
  ICMP Header
  	|-Type     : 64
  	|-Code     : 0
  	|-Checksum : 16385
  
  Dump
    00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 ..............E.
    00 54 0D 0E 40 00 40 01 38 BE AC 14 4E 5A AC 14 .T..@.@.8...NZ..
    4E 5A 08 00 A4 22 50 0E 00 01 BD 92 BD 5D 00 00 NZ..."P......]..
    00 00 C2 0A 08 00 00 00 00 00 10 11 12 13 14 15 ................
    16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 .......... !"#$%
    26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 &'()*+,-./012345
    36 37                                           67
  *****************************************************************
  ```

### 上层模块：

- [x] 数据包、协议统计模块

  ```shell
  START: Fri Nov  1 18:25:15 2019
  |-Total: 10387 (BYTE SPEED:)
  	|-ARP: 3253
  	|-IP: 6364 (2232323 bytes)
  		|-ICMP: 28
  			|-TTL EXPIRED: 11
  			|-ECHO REPLY: 0
  			|-REDIRECT: 5
  			|-UNREACHABLE: 3
  		|-TCP: 3713
  		|-UDP: 2429
  		|-Other IP: 194
  	|-Other: 770
  |-MAC BROAD:
  |-MAC SHORT:
  |-MAC LONG:
  |-IP BROAD:
  |-NEW MACs:
  	AB-CD-EF-12-34-56
  END: Fri Nov  1 18:32:03 2019
  ```

- [x] 网络网元发现模块

  ```shell
  C8-FF-28-3D-71-FD
  58-69-6C-A5-E2-D3
  00-00-00-00-00-00
  FF-FF-FF-FF-FF-FF
  ```

- [x] 数据包构造模块(选做)

- [x] 数据包过滤模块

- [x] 命令行参数解析

  ```shell
  $ ./a.out --help
  Usage: a.out [OPTION...] [PROTOCOLS...]
  Sniffer w/ RAW SOCKET -- a program sniffs local network traffic, build upon raw
  socket...
  options
  
    -a, --all                  Log all packets
    -d, --dump                 Include packet dump
    -e, --ethernet             Include ethernet header
    -i, --interface=ifname     Capture packets on ifname
    -p, --port=port            Filter port
    -?, --help                 Give this help list
        --usage                Give a short usage message
  
  Mandatory or optional arguments to long options are also mandatory or optional
  for any corresponding short options.
  
  You Need To Have Root Permission to Use Raw Socket!
  ```

* refs
  * [bind raw socket to specific interface](https://stackoverflow.com/questions/3998569/how-to-bind-raw-socket-to-specific-interface)

