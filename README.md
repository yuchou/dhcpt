DHCPv4 and DHCPv6测试工具

Doc:
	
Usage:
    dhcpt.py [-h -6 -r -i -c]

Options:
    -h	--help			<--欢迎查看使用帮助文档 :)
    -6	--ipv6          ...使用DHCPv6协议,DHCPv4[默认]
    -r  --release		...使用DHCP协议释放IP地址
                        ...使用DHCP协议申请IP地址[默认]
    -i	--interface		...指定发包网口,eth0[默认]
    -c  --count			...模拟客户机数,10[默认] "
"""

examples:
1.python dhcpt.py		#使用dhcpv4协议，eth0口发送DHCP请求包

2.python dhcpt.py -r 	#使用dhcpv4协议，eth0口发送DHCP释放包