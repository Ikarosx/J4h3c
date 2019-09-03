package cn.ikarosx.caputure;

import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

class AuthPacket {

  private static final int READ_TIMEOUT = 10;
  private static final int SNAPLEN = 65536;
  private static final int BUFFER_SIZE = 1024 * 1024;
  private static final boolean TIMESTAMP_PRECISION_NANO = false;
  private static String userName;
  private static EthernetPacket.Builder packetBuilder = new EthernetPacket.Builder();
  // 版本号和密钥通过 bitdust/H3C_toolkit 中的version_sniff工具获得，dalao...
  private static final String INODE_VERSION = "ENV7.10-0309";
  private static final String HUAWEI_KEY = "Oly5D62FaE94W7";
  private static Scanner scanner = new Scanner(System.in);

  static void setUserName(String userName) {
    AuthPacket.userName = userName;
  }

  static void setPassword(String password) {
    AuthPacket.password = password;
  }

  private static String password;
  /**
   * 发送Start或者Logoff报文
   *
   * @param nif 网卡接口
   * @param sl 发送报文的类型，Start或Logoff
   */
  static void sendStartOrLogoffPacket(PcapNetworkInterface nif, StartLogoff sl) {
    EthernetPacket.Builder builder = new EthernetPacket.Builder();
    /*
       802.1X
       1,2,0,0
       Version:1 代表802.1X 2001
       Type:1 表示Start 2 表示Logoff
       0 0 作补充位
    */
    byte startLogoff = sl == StartLogoff.Start ? (byte) 1 : (byte) 2;
    byte[] padArr = {1, startLogoff, 0, 0};
    // 取得本地的MAC地址
    MacAddress srcAddr = (MacAddress) nif.getLinkLayerAddresses().get(0);
    // 构造以太网数据包
    EthernetPacket packet =
        builder
            .srcAddr(srcAddr) // 本地MAC地址
            .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS) // 目的地MAC地址，这里为广播地址
            .type(new EtherType((short) 0x888E, "H3C")) // 协议类型
            .pad(padArr) // 在协议类型之后填充数据为padArr
            .build();
    PcapHandle loginHandle;
    try {
      // 设置每个报文截取的数据长度为65536字节，并设置网卡工作模式为混杂模式，超时时长为10ms
      loginHandle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
      // 发送包
      loginHandle.sendPacket(packet);
    } catch (NotOpenException | PcapNativeException e) {
      e.printStackTrace();
    }
  }
  /**
   * 发送Identity报文
   *
   * @param nif 网卡接口
   * @param data 接收到的报文数据
   */
  static void SendResponseIdentity(PcapNetworkInterface nif, byte[] data) {
    byte[] dstAddrByte = new byte[6];
    // 从接收到的数据中取出目的地的MAC地址
    System.arraycopy(data, 6, dstAddrByte, 0, 6);
    MacAddress srcAddr = (MacAddress) nif.getLinkLayerAddresses().get(0);
    MacAddress dstAddr = MacAddress.getByAddress(dstAddrByte);
    // pad用作填充，长度为如下注释的17字节 + MD5的28字节 + 2个固定字节 + 用户名的长度
    byte[] pad = new byte[17 + 30 + userName.length()];
    /*
        17字节
        802.1X 4字节
        Version： 01 代表802.1X-2001
        Type： 00 代表 EAP包
        Length：  代表EAP部分的长度

        EAP 13字节
        CODE：02 代表类型为Response
        ID：     与收到服务器的请求的报文ID相同
        Length： 代表EAP部分的长度
        Type：01 代表Identity
        固定：15 04
        IP：4位  代表本机IP
        固定：06 07
    */
    // 获取IPV4的地址
    byte[] ipv4Bytes = getIPV4(nif);
    // 构造17字节的数组
    byte[] prePad = {
      0x01,
      0x00,
      0x00,
      (byte) (43 + userName.length()),
      0x02,
      data[19],
      0x00,
      (byte) (43 + userName.length()),
      0x01,
      0x15,
      0x04,
      ipv4Bytes[0],
      ipv4Bytes[1],
      ipv4Bytes[2],
      ipv4Bytes[3],
      0x06,
      0x07
    }; // 17
    // 将该数组填充到pad中
    System.arraycopy(prePad, 0, pad, 0, prePad.length);
    // 获取加密后的版本号bytes数组
    byte[] encryptVersionBytes = EncryptVersion(); // 28
    System.arraycopy(encryptVersionBytes, 0, pad, 17, encryptVersionBytes.length);
    // 填充2个固定字节，与28字节的加密版本号组成30字节
    pad[45] = pad[46] = 0x20;
    // 填充用户名bytes数组
    System.arraycopy(userName.getBytes(), 0, pad, 47, userName.length());
    EthernetPacket packet =
        packetBuilder
            .srcAddr(srcAddr)
            .dstAddr(dstAddr)
            .type(new EtherType((short) 0x0888E, "H3C"))
            .pad(pad)
            .build();
    PcapHandle sendHandle;
    try {
      sendHandle =
          nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
      sendHandle.sendPacket(packet);
      System.out.println("Send Response Identity.");
    } catch (PcapNativeException | NotOpenException e) {
      e.printStackTrace();
    }
  }
  /**
   * 从接口取得ipv4地址
   *
   * @param nif 网卡接口
   * @return IPV4地址的字节数组
   */
  private static byte[] getIPV4(PcapNetworkInterface nif) {
    // 获取IP地址列表
    List<PcapAddress> addresses = nif.getAddresses();
    // 如果地址列表有两个
    if (addresses.size() == 2) {
      // 如果两个地址相同，说明只存在IPV6
      if (addresses
          .get(1)
          .getAddress()
          .getHostAddress()
          .equals(addresses.get(0).getAddress().getHostAddress())) {
        throw new RuntimeException("Get IPV4 Failed.");
      } else {
        // 两个地址不同，返回后面一个IP
        return addresses.get(1).getAddress().getAddress();
      }
    } else if (addresses.size() == 1) {
      // 只有一个地址，返回列表中为1
      return addresses.get(0).getAddress().getAddress();
    } else {
      // 其他数量的地址
      throw new RuntimeException("Get IPV4 Failed");
    }
  }
  /**
   * 加密客户端版本号
   *
   * @return 返回加密版本号后的字节数组
   */
  private static byte[] EncryptVersion() {
    // ①生成随机数，将其表示为8位数的16进制，不足补零
    int random = Random();
    String random32 = String.format("%08x", random);
    // ②
    // 对版本号不足16位补零
    byte[] versionBytesNotZero = INODE_VERSION.getBytes();
    byte[] versionBytesZero = new byte[16];
    for (int i = 16 - versionBytesNotZero.length; i < 16; i++) {
      versionBytesZero[i] = 0x0;
    }
    System.arraycopy(versionBytesNotZero, 0, versionBytesZero, 0, versionBytesNotZero.length);
    // 随机数与版本号异或
    XOR(versionBytesZero, random32.getBytes());
    // ③将4字节随机数附加在加密后，形成20字节
    // 将字符串转成byte数组
    byte[] twentyBytes = new byte[20];
    for (int i = 0; i < 4; i++) {
      String substring = random32.substring(i * 2, i * 2 + 2);
      int x = Integer.parseInt(substring, 16);
      twentyBytes[16 + i] = (byte) x;
    }
    System.arraycopy(versionBytesZero, 0, twentyBytes, 0, versionBytesZero.length);
    // ④将20字节与华为密钥异或
    XOR(twentyBytes, HUAWEI_KEY.getBytes());
    // ⑤将加密字符base64编码后即为最终加密结果
    return Base64.getEncoder().encode(twentyBytes);
  }

  /**
   * 通过ID、密码与返回的MD5值进行MD5加密
   *
   * @param pad 要填充的数组
   * @param id 接收到的ID
   * @param pwd 用户密码
   * @param data 接收到的报文数据
   */
  private static void FillMD5Area(byte[] pad, byte id, String pwd, byte[] data) {
    // 密码长度和信息长度
    int pwdLen = pwd.length();
    int msgLen = 1 + pwdLen + 16;
    // 信息缓冲区
    byte[] msgBuf = new byte[msgLen];
    // 填充数据
    msgBuf[0] = id;
    System.arraycopy(pwd.getBytes(), 0, msgBuf, 1, pwdLen);
    System.arraycopy(data, 24, msgBuf, 1 + pwdLen, 16);
    // 计算MD5值
    byte[] md5 = new byte[0];
    try {
      md5 = MessageDigest.getInstance("md5").digest(msgBuf);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    System.arraycopy(md5, 0, pad, 10, md5.length);
  }

  /**
   * 发送MD5响应报文
   *
   * @param nif 网卡接口
   * @param data 接收到的报文数据
   */
  static void SendResponseMD5(PcapNetworkInterface nif, byte[] data) {
    byte[] srcAddrByte = new byte[6];
    byte[] dstAddrByte = new byte[6];
    // 从接收到的数据里面获取MAC地址
    System.arraycopy(data, 0, srcAddrByte, 0, 6);
    System.arraycopy(data, 6, dstAddrByte, 0, 6);
    MacAddress srcAddr = MacAddress.getByAddress(srcAddrByte);
    MacAddress dstAddr = MacAddress.getByAddress(dstAddrByte);
    // 准备填充数据
    byte[] pad = new byte[46];
    /*
        10字节
        802.1X 4字节
        Version： 01
        Type： 00
        Length：

        EAP 6字节
        CODE：02
        ID：
        Length：
        Type：04
        EAP-MD5-Value Size: 10
    */
    byte length = (byte) (22 + userName.length());
    byte[] prePad = {0x01, 0x00, 0x00, length, 0x02, data[19], 0x00, length, 0x04, 0x10};
    System.arraycopy(prePad, 0, pad, 0, prePad.length);
    // 填充MD5加密数据
    FillMD5Area(pad, data[19], password, data);
    // 填充用户名数据
    System.arraycopy(userName.getBytes(), 0, pad, 26, userName.length());
    EthernetPacket packet =
        packetBuilder
            .srcAddr(srcAddr)
            .dstAddr(dstAddr)
            .type(new EtherType((short) 0x0888E, "H3C"))
            .pad(pad)
            .build();
    System.out.println("Send Response MD5.");
    PcapHandle sendHandle;
    try {
      sendHandle =
          nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
      sendHandle.sendPacket(packet);
    } catch (PcapNativeException | NotOpenException e) {
      e.printStackTrace();
    }
  }

  /**
   * 使用密钥key[]对数据data[]进行异或加密 该函数也可反向用于解密
   *
   * @param data 要异或的数据
   * @param key 密钥
   */
  private static void XOR(byte[] data, byte[] key) {
    int i, j;
    int dataLen = data.length;
    int keyLen = key.length;
    // 先按正序处理一遍
    for (i = 0; i < dataLen; i++) {
      data[i] ^= key[i % keyLen];
    }
    // 再按倒序处理第二遍
    for (i = dataLen - 1, j = 0; j < dataLen; i--, j++) {
      data[i] ^= key[j % keyLen];
    }
  }

  /**
   * 生成随机正整数数，通过时间做种子
   *
   * @return 返回一个随机正整数
   */
  private static int Random() {
    long seed = System.currentTimeMillis();
    Random r = new Random(seed);
    return Math.abs(r.nextInt());
  }
  /**
   * 获取输入序号，并判断格式
   *
   * @return 选择的网卡序号
   */
  static int getIndex() {
    int i = 0;
    System.out.println("请选择你的网卡：");
    // 遍历所有网卡的描述，MAC地址，IPV4和IPV6地址
    try {
      for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
        List<PcapAddress> addresses = dev.getAddresses();
        System.out.println(
            i++
                + "\tDescription:"
                + dev.getDescription()
                + "\t\tMAC:"
                + dev.getLinkLayerAddresses()
                + "\t\tIPV4:"
                + (addresses.size() == 2
                    ? addresses
                            .get(1)
                            .getAddress()
                            .getHostAddress()
                            .equals(addresses.get(0).getAddress().getHostAddress())
                        ? "null"
                        : addresses.get(1).getAddress().getHostAddress()
                    : "null")
                + "\t\tIPV6:"
                + addresses.get(0).getAddress().getHostAddress());
      }
    } catch (PcapNativeException e) {
      e.printStackTrace();
    }
    int index;
    System.out.println("请输入网卡序号，按q退出：");
    do {
      // 获取所输入的序号
      String str = scanner.next();
      if (str.toLowerCase().equals("q")) {
        System.exit(0);
      }
      try {
        index = Integer.parseInt(str);
      } catch (NumberFormatException nfe) {
        System.out.println("请输入正确格式的数字，或者q");
        continue;
      }
      if (index < 0 || index >= i) {
        System.out.println("请输入正确范围的序号");
        continue;
      }
      break;
    } while (true);
    return index;
  }
}
