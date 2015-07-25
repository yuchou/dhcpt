#!/usr/bin/env python
# -*- coding: utf-8 -*-
#@by yuchou

"""
DHCPv4 and DHCPv6测试工具

Doc:

Usage:
    dhcpt.py [-h -6 -r -i -c]

Options:
    -h	--help			<--欢迎查看使用帮助文档 :)
    -6	--ipv6                  ...使用DHCPv6协议,DHCPv4[默认]
    -r  --release		...使用DHCP协议释放IP地址
                                ...使用DHCP协议申请IP地址[默认]
    -i	--interface		...指定发包网口,eth0[默认]
    -c  --count			...模拟客户机数,10[默认] "
"""

import subprocess,logging,random,sys,threading,time,getopt,fcntl,signal,os
from sys import stdout

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *
except ImportError:
    print "Scapy package for Python is not installed on your system."
    print "Get it from https://pypi.python.org/pypi/scapy and try again."
    sys.exit()

################## GLOBAL CONFIG #################
conf.checkIPaddr = False
conf.iface = "eth0"
MODE_IPV4 = True
MODE_IPV6 = False
MODE_REQ = True
MODE_RELEASE = False
THREAD_CNT = 1
THREAD_POOL = []
PKT_INF = conf.iface
PKT_NO = "10"
DHCP_FILE = 'DHCP_Leases.txt_'
VERBOSITY = True

#日志接口
def LOG(message=None,logtype=None):
    if VERBOSITY:
        stdout.write("[{0}]-->{1}\n" .format(logtype,message))
        stdout.flush()

#设置网卡模式  //暂时未用到
def Net_Iface_Mode(net_iface):
    if ( sys.platform == 'win32' ):
        LOG(logtype="ERROR",message="请使用linux！")
    else:
        subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)

#信号机制
def signal_handler(signal, frame):
    LOG(logtype="NOTICE", message= ' -----  ABORT ...  -----')
    i = 0
    for t in THREAD_POOL:
        t.kill_received = True
        LOG(logtype="DEBUG", message= 'Waiting for Thread [{0}] to die ...'.format(i))
        i+=1
    sys.exit(0)

#参数检查
def checkArgs():
    global MODE_IPV4,MODE_IPV6,MODE_REQ,MODE_RELEASE,THREAD_CNT,PKT_INF,PKT_NO,VERBOSITY
    try:
        opts,args = getopt.getopt(sys.argv[1:],"h6ri:c:t:",
                [
                    "help",
                    "ipv6",
                    "release",
                    "interface=",
                    "count=",
                    "thread="
                    ])
    except getopt.GetoptError,err:
        #print str(err)
        Usage()
        sys.exit(2)

    for option,value in opts:
        if option in ("-h","--help"):
            Usage()
            sys.exit()
        elif option in ("-6","--ipv6"):
            MODE_IPv6 = True
            MODE_IPV4 = False
        elif option in ("-r","--release"):
            MODE_RELEASE = True
            MODE_REQ = False
        elif option in ("-i","--interface"):
            PKT_INF = value
            Net_Iface_Mode(value)
        elif option in ("-c","--count"):
            PKT_NO = value
        elif option in ("-t","--thread"):
            THREAD_CNT = int(value)
        else:
            assert False, "Unhandled option"

    #if len(args) <= 1:
    #    Usage()
    #    sys.exit(2)

################## DHCP SEQUENCE #################
def Generate_Dhcp_Seq():

    #定义dhcp参数
    x_id = random.randrange(1, 1000000)
    hw = "00:00:5e" + str(RandMAC())[8:]
    hw_str = mac2str(hw)

    #模拟创建和发送dhcp discover包
    dhcp_dis_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=hw)/IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67)/BOOTP(op=1, xid=x_id, chaddr=hw_str)/DHCP(options=[("message-type","discover"),("client_id",hw_str),("end")])
    answd, unanswd = srp(dhcp_dis_pkt, iface=PKT_INF, timeout = 5, verbose=0)
    offered_ip = answd[0][1][BOOTP].yiaddr
    server_src = answd[0][1][IP].src

    #模拟创建和发送dhcp request包
    dhcp_req_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=hw)/IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67)/BOOTP(op=1, xid=x_id, chaddr=hw_str)/DHCP(options=[("message-type","request"),("requested_addr", offered_ip),("client_id",hw_str),("server_id",server_src),("end")])
    answr, unanswr = srp(dhcp_req_pkt, iface=PKT_INF, timeout = 5, verbose=0)
    offered_ip_ack = answr[0][1][BOOTP].yiaddr

    #提取DHCP Server IP、ACK、client_mac
    server_ip = answr[0][1][IP].src
    
    LOG(logtype = "NOTICE", message = "已获取IP[{0}]!".format(offered_ip))

    return offered_ip_ack, server_ip, hw

################## DHCP RELEASE #################
def Generate_Dhcp_Release(ip, server, hw):
    #定义dhcp参数
    x_id = random.randrange(1, 1000000)
    hw_str = mac2str(hw)
    #创建dhcp release包
    dhcp_rls_pkt = IP(src=ip,dst=server) / UDP(sport=68,dport=67)/BOOTP(chaddr=hw_str, ciaddr=ip, xid=x_id)/DHCP(options=[("message-type","release"),("server_id", server),("end")])

    #发送dhcp包
    send(dhcp_rls_pkt, verbose=0)
    LOG(logtype = "NOTICE", message = "已释放IP[{0}]!".format(ip))

class Do_Req(threading.Thread):
    global all_leased_ips,t_pool
    def __init__ (self):
        threading.Thread.__init__(self)
        self.kill_received = False
        self.t_pool = len(THREAD_POOL)

    def run(self):
        while not self.kill_received:
            try:
                #调用DHCP请求函数
                LOG(logtype = "NOTICE", message = "THREAD[{0}]我要请求开始了！你准备好了吗？".format(str(self.t_pool)))
                for iterate in range(0, int(PKT_NO)):
                    leased_ips = Generate_Dhcp_Seq()
		    #把申请到的IP地址的对应关系写到DHCP_Leases.txt文件
                    dhcp_leases = open(DHCP_FILE + str(self.t_pool), "a")
                    print >>dhcp_leases, leased_ips[0] + "," + leased_ips[1] + "," + leased_ips[2]
                    dhcp_leases.close()
            except IndexError,err:
                #print str(err)
                LOG(logtype = "ERROR", message = "THREAD[{0}]未检测到DHCP服务或连接被拒绝,请检查你的网络配置并尝试重试.".format(str(self.t_pool)))
                sys.exit()

class Do_Release(threading.Thread):
    global t_pool
    def __init__ (self):
        threading.Thread.__init__(self)
        self.kill_received = False
        self.t_pool = len(THREAD_POOL)

    def run(self):
        while not self.kill_received:
            if os.path.isfile(DHCP_FILE + str(self.t_pool)) is False or os.stat(DHCP_FILE + str(self.t_pool)).st_size == 0:
                LOG(logtype = "ERROR", message = "THREAD[{0}]{1}{0}文件不存在或已被清空！退出进程！".format(str(self.t_pool),DHCP_FILE))
                sys.exit(2)
            else:
                try:
                    LOG(logtype = "NOTICE", message = "THREAD[{0}]我要开始释放了！你准备好了吗？".format(str(self.t_pool)))
                    #检查ip地址，并调用dhcp释放函数
                    for line in open(DHCP_FILE+str(self.t_pool)):
                        argline = line.split(",")
                        #LOG(logtype="NOTICE",message="argline[0]={0},argline[1]={1},argline[2]={2}".format(argline[0],argline[1],argline[2]))
                        Generate_Dhcp_Release(argline[0], argline[1], argline[2])
                    open(DHCP_FILE + str(self.t_pool), "w").close()
                    LOG(logtype = "NOTICE", message = "THREAD[{0}]{1}{0}文件已被清空！".format(str(self.t_pool),DHCP_FILE))
                except (NameError, IndexError),err:
                    LOG(logtype = "ERROR", message = "THREAD[{0}！".format(err))
                    LOG(logtype = "ERROR", message = "THREAD[{0}释放失败，请检查配置！退出程序！".format(str(self.t_pool)))
                    sys.exit(2)

#主函数
def main():
    global THREAD_POOL
    checkArgs()
    LOG(logtype = "NOTICE", message = "- using interface {0}".format(conf.iface))
    signal.signal(signal.SIGINT, signal_handler)
    if MODE_IPV4 and MODE_REQ:
       # print 'here1'
        for i in range(THREAD_CNT):
            LOG(logtype = "DEBUG", message = "THREAD [{0}]-- READY (DO REQUEST)".format(len(THREAD_POOL)))
            t = Do_Req()
            t.start()
            THREAD_POOL.append(t)

    elif MODE_IPV4 and MODE_RELEASE:
        for i in range(THREAD_CNT):
            LOG(logtype = "DEBUG", message = "THREAD [{0}] -- READY (DO RELEASE)".format(len(THREAD_POOL)))
            t = Do_Release()
            t.start()
            THREAD_POOL.append(t)

#帮助说明
def Usage():
    print __doc__

if __name__ == "__main__":
    main()
    print "\n"
