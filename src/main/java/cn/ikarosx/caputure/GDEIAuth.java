package cn.ikarosx.caputure;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.List;

public class GDEIAuth {
  private static final int READ_TIMEOUT = 10;
  private static final int SNAPLEN = 65536;
  private static final int BUFFER_SIZE = 1024 * 1024;
  private static final boolean TIMESTAMP_PRECISION_NANO = false;

  public static void main(String[] args) {

    if (args.length != 2) {
      System.out.println("请正确输入用户名和密码，格式如 java -jar InodeAuth.jar username password");
      System.exit(0);
    }
    // 赋值用户密码
    AuthPacket.setUserName(args[0]);
    AuthPacket.setPassword(args[1]);
    try {
      List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
      // 遍历网卡并获取用户输入的网卡序号
      int index = AuthPacket.getIndex();
      PcapNetworkInterface nif = allDevs.get(index);
      // 发送logoff的数据包
      AuthPacket.sendStartOrLogoffPacket(nif, StartLogoff.Logoff);
      AuthPacket.sendStartOrLogoffPacket(nif, StartLogoff.Logoff);
      try {
        // 等待1s，防止出现意外毛病
        Thread.sleep(1000);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
      // 发送Start数据包两次
      AuthPacket.sendStartOrLogoffPacket(nif, StartLogoff.Start);
      AuthPacket.sendStartOrLogoffPacket(nif, StartLogoff.Start);
      // 创建构建者
      PcapHandle.Builder phb =
          new PcapHandle.Builder(nif.getName())
              .snaplen(SNAPLEN)
              .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
              .timeoutMillis(READ_TIMEOUT)
              .bufferSize(BUFFER_SIZE);
      if (TIMESTAMP_PRECISION_NANO) {
        phb.timestampPrecision(PcapHandle.TimestampPrecision.NANO);
      }
      // 构建handle
      PcapHandle handle = phb.build();
      /*
       过滤出属于802.1X协议的包，不包括MAC地址为自身的包 过滤规则参考Berkeley Packet Filter,BPF
       https://www.winpcap.org/docs/docs_40_2/html/group__language.html
      */
      String filter =
          "ether proto 0x888E and (not ether src "
              + nif.getLinkLayerAddresses().get(0).toString()
              + ")";
      handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
      // 循环接收来自服务器的数据报文
      while (true) {
        Packet nextPacket = handle.getNextPacket();
        if (nextPacket == null) {
          continue;
        }
        // 获取报文中的数据
        byte[] rawData = nextPacket.getRawData();
        // 判断EAP报文中的请求代码，即rawData中第18字节的值 Code
        switch (rawData[18]) {
          case 1: // Code = 1 ：Request
            {
              System.out.print("Receive:Code is Request,");
              // 第二次判断，判断Request类型 Type
              switch (rawData[22]) {
                case 1: // Type = 1 ： Identity

                  /*
                   这里有两个作用
                   ①发送Start数据包过去之后，会返回一个Request包，此时应该发送Identity报文
                   ②认证成功后，会定时返回一个Request包，此时发送Identity作为心跳包
                  */
                  {
                    System.out.println("type is identity.");
                    AuthPacket.SendResponseIdentity(nif, rawData);
                    break;
                  }
                case 2: // Type = 2 ： Notification TODO
                  /*
                      The Notification Type is optionally used to convey a displayable
                    message from the authenticator to the peer.  An authenticator MAY
                    send a Notification Request to the peer at any time when there is
                    no outstanding Request, prior to completion of an EAP
                    authentication method.  The peer MUST respond to a Notification
                    Request with a Notification Response unless the EAP authentication
                    method specification prohibits the use of Notification messages.
                    In any case, a Nak Response MUST NOT be sent in response to a
                    Notification Request.  Note that the default maximum length of a
                    Notification Request is 1020 octets.  By default, this leaves at
                    most 1015 octets for the human readable message.
                  */
                  {
                    System.out.println("type is notification.");
                    break;
                  }

                case 4: // Type = 4 ： MD5-Challenge EAP
                  // 发送Identity报文之后，会返回一个带有MD5密文的包，此时应该发送响应的MD5报文
                  // 发送两次（客户端是这么做的，我也学他
                  {
                    System.out.println("type is MD5-Challenge EAP.");
                    AuthPacket.SendResponseMD5(nif, rawData);
                    AuthPacket.SendResponseMD5(nif, rawData);
                    break;
                  }
                case 20: // TODO
                  /*
                   The original EAP method Type space has a range from 1 to 255, and is
                  the scarcest resource in EAP, and thus must be allocated with care.
                  Method Types 1-45 have been allocated, with 20 available for re-use.
                  Method Types 20 and 46-191 may be allocated on the advice of a
                  Designated Expert, with Specification Required.
                  */
                  {
                    System.out.println("type is Specification Required");
                    break;
                  }
                default:
                  {
                    System.out.println("unexpected, type is " + rawData[22]);
                    break;
                  }
              }
            }
            break;
          case 3: // code = 3 : Success
            {
              System.out.println("认证成功！");
              break;
            }
          case 4: // code = 4 : Failed
            {
              System.out.println("认证失败!");
              AuthPacket.sendStartOrLogoffPacket(nif, StartLogoff.Logoff);
              AuthPacket.sendStartOrLogoffPacket(nif, StartLogoff.Start);
              break;
            }
          default:
            {
              System.out.println("UnExpected: Receive: Code is" + rawData[18]);
              break;
            }
        }
      }
    } catch (PcapNativeException | NotOpenException e) {
      e.printStackTrace();
    }
  }
}
