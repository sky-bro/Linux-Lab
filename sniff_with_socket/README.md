* linux中网卡设置混杂promiscuous模式
  * ip 
* 数据链路访问接口定义

## 数据包监控程序

### 底层模块

- [x] 数据包的捕获过程

### 中层模块：协议分析模块

- [x] MAC层处理
- [x] IP层处理
- [x] TCP处理模块
- [x] UDP处理模块
- [x] ICMP处理模块

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

- [x] 数据包构造模块(选做)

- [x] 数据包过滤模块

- [x] 命令行参数解析

[bind raw socket to specific interface](https://stackoverflow.com/questions/3998569/how-to-bind-raw-socket-to-specific-interface)