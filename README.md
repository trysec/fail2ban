简介
---
fail2ban 一键安装 \ 卸载脚本

环境
---
支持OS : `CentOS \ Debian \ Ubuntu`

使用
---
```
wget "https://raw.githubusercontent.com/qinghuas/fail2ban/master/fail2ban.sh"
```
![image](https://i.loli.net/2018/02/15/5a8533967e7f1.png)

详解
---
安装 : `bash fail2ban.sh install`

卸载 : `bash fail2ban.sh uninstall`

查看运行日志 : `bash fail2ban.sh runlog`

查看更多信息 : `bash fail2ban.sh more`

服务
---
启动 : `bash fail2ban.sh start`

停止 : `bash fail2ban.sh stop`

重启 : `bash fail2ban.sh restart`

查看状态 : `bash fail2ban.sh status`

封禁
---
解除封禁 : `bash fail2ban.sh {unlock|ul}`

快捷解除封禁 : `bash fail2ban.sh {unlock|ul} ip` , e.g : `bash fail2ban.sh ul 123.123.123.123`

查看封禁列表 : `bash fail2ban.sh {blocklist|bl}`

注：`bl` 为 `block list` 简拼 ，`ul` 为 `un lock` 简拼，使用上是等效的

日志
---
`2018-02-15` : 创建

更多
---
https://www.fail2ban.org  
https://linux.cn/article-5067-1.html
