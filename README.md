# DDNS_cpp
----

#### C++实现的DDNS
 - 仅支持windows
 - 仅支持阿里云

#### Using:
 - 配置好```config.yaml```
 - 双击 ```DDns_cpp.exe```
 - Enjoy~

#### 配置文件 [config/config.yaml]

```yaml
# 阿里云Key
AliKeyConfig:
  "AccessKeyId": ""
  "AccessKeySecret": ""
#分钟
DelayTime: 10
IpvConfig:
  #CA_IPV6
  - Type: IPV6 # [IPV4,IPV6]
    Domain: dog.cn # Domain
    Subdomain: ddns6ca # Subdomain
    Cloud: ALICLOUD # 云平台
    Enable: FALSE # [TRUE, FALSE], FALSE时不会执行此配置
    TTL: 600 # TTL 600
    Provider: NETWORK # [SSH_OPENWRT，NETWORK，MACHINE] IP来源
    # 以下根据Provider配置选填
    NetworkConfig: # 字符串数组，Provider为[NETWORK]时 此项必填
      - "https://ipv6.ddnspod.com/"
    SSHConfig: # SSH配置，Provider为[SSH_OPENWRT]时 此项必填
      Host: 10.10.10.1
      Port: 22
      User: root
      Password: password
      InterfaceName: pppoe-wan # openwrt中wan口的名字，登录ssh执行命令：ip addr 可查看， 
  #CA_IPV4
  - Type: IPV4
    Domain: dog.cn
    Subdomain: ddns4ca
    Cloud: ALICLOUD
    Enable: TRUE
    TTL: 600
    Provider: SSH_OPENWRT
    NetworkConfig:
      - "https://jsonip.com"
      - "https://ip.xrdp.cc"
    SSHConfig:
      Host: dog.cn
      Port: 2223
      User: root
      Password: wrt
      InterfaceName: pppoe-wan

```