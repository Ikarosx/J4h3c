# IkarosH3C
基于[J4h3c](https://github.com/XJhrack/J4h3c/releases)二次开发

## 实现功能
目前只负责认证，IP需手动设置为固定IP
经过测试可用于广东第二师范学院网线认证上网 ——2019-9-3

## 依赖开发环境
* Linux/openWRT: libpcap
* Windows: WinPcap
* JDK8及其以上

## 使用方法
命令行：
  java -jar GDEIAuth.jar username password
* 参数1-用户名
* 参数2-密码

## 下载
IkarosH3C：[下载地址](https://github.com/Ikarosx/IkarosH3C/releases)

## 感谢
* [H3C](https://github.com/QCute/H3C)
* [Pcap4J](https://github.com/kaitoy/pcap4j)
* [J4h3c](https://github.com/XJhrack/J4h3c)

## 参考
* [伯克利包过滤语法](https://www.winpcap.org/docs/docs_40_2/html/group__language.html)(Berkeley Packet Filter,BPF)
* [Inode客户端抓包分析流程](https://fjkfwz.github.io/2014/12/04/H3C-inode-Linux/)
