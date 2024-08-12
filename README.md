# BetterCloudflare

开发中.....代码跑不起来，文档缺失请见谅...........

## 介绍

一个针对Cloudflare自选开发的工具集，包括Colo筛选，官方/SNIproxy 可用性检查，SNI代理线路测试筛选，EdgeNode测速（开发中）....

此脚本仅限交流学习，请勿滥用！！

此脚本拿脚写的，代码质量垃圾到没法看，看不惯请关闭该标签页

欢迎PR！

## 参数说明
-i, --input：输入文件路径，包含目标主机列表，每行一个。

-o, --output：输出文件路径，用于存储结果，默认在当前目录。

-C, --colo：启用Colo检查模式。

-N, --node_list：检查并处理输入文件中的节点列表。

-R, --route：对输入文件中的每个目标执行路由追踪。

-S, --speedtest：对输入文件中的每个目标执行速度测试。

-ip2asn_db：指定IP2ASN数据库文件的路径。

-length：速度测试使用的文件大小，默认为10MB。

--threads：速度测试时使用的线程数，默认为10。

--timeout：速度测试的超时时间，默认为30秒。



A simple toolbox for cloudflare edge node selection
