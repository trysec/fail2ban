# 简介

fail2ban 一键安装 / 卸载脚本。

支持自动检测系统环境，并配置合适的防火墙和日志方案。

# 环境

支持的操作系统：

- **RHEL 系列**: CentOS 7/8/9, RHEL 7/8/9, Rocky Linux 8/9, AlmaLinux 8/9, Fedora
- **Debian 系列**: Debian 9/10/11/12, Ubuntu 18.04/20.04/22.04/24.04
- **Windows**: Windows 10/11, Windows Server（PowerShell 版，依赖 OpenSSH Server 与 Windows Defender Firewall）

自动检测特性：

- ✅ **防火墙自动适配**: firewalld / nftables / iptables
- ✅ **日志系统自动检测**: journald / rsyslog / syslog-ng
- ✅ **服务管理器自动适配**: systemd / sysvinit
- ✅ **包管理器自动选择**: dnf / yum / apt-get

# 使用

```bash
wget "https://raw.githubusercontent.com/trysec/fail2ban/refs/heads/master/fail2ban.sh"
```

![image](https://i.loli.net/2018/02/15/5a8533967e7f1.png)

Windows 使用：

```powershell
powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 install
```

Windows 本地一键安装：

```bat
install-win.bat
```

Windows 本地一键卸载：

```bat
uninstall-win.bat
```

Windows GitHub 一键安装：

```powershell
$script = Join-Path $env:TEMP 'fail2ban.ps1'
Invoke-WebRequest 'https://raw.githubusercontent.com/trysec/fail2ban/master/fail2ban.ps1' -OutFile $script
& $script install
```

Windows GitHub 一键卸载：

```powershell
$script = Join-Path $env:TEMP 'fail2ban.ps1'
Invoke-WebRequest 'https://raw.githubusercontent.com/trysec/fail2ban/master/fail2ban.ps1' -OutFile $script
& $script uninstall
```

Windows CMD 一键安装：

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$script = Join-Path $env:TEMP 'fail2ban.ps1'; Invoke-WebRequest 'https://raw.githubusercontent.com/trysec/fail2ban/master/fail2ban.ps1' -OutFile $script; & $script install"
```

Windows CMD 一键卸载：

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$script = Join-Path $env:TEMP 'fail2ban.ps1'; Invoke-WebRequest 'https://raw.githubusercontent.com/trysec/fail2ban/master/fail2ban.ps1' -OutFile $script; & $script uninstall"
```

# 详解

安装 : `bash fail2ban.sh install`

卸载 : `bash fail2ban.sh uninstall`

查看运行日志 : `bash fail2ban.sh runlog`

查看更多信息 : `bash fail2ban.sh more`

Windows 安装 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 install`

Windows 卸载 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 uninstall`

Windows 本地一键安装 : `install-win.bat`

Windows 本地一键卸载 : `uninstall-win.bat`

Windows 查看运行日志 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 runlog`

Windows 查看更多信息 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 more`

# 服务

启动 : `bash fail2ban.sh start`

停止 : `bash fail2ban.sh stop`

重启 : `bash fail2ban.sh restart`

查看状态 : `bash fail2ban.sh status`

Windows 启动 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 start`

Windows 停止 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 stop`

Windows 重启 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 restart`

Windows 查看状态 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 status`

# 封禁

解除封禁 : `bash fail2ban.sh {unlock|ul}`

快捷解除封禁 : `bash fail2ban.sh {unlock|ul} ip` , e.g : `bash fail2ban.sh ul 123.123.123.123`

查看封禁列表 : `bash fail2ban.sh {blocklist|bl}`

Windows 解除封禁 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 {unlock|ul}`

Windows 快捷解除封禁 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 {unlock|ul} ip`

Windows 查看封禁列表 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 {blocklist|bl}`

注：`bl` 为 `block list` 简拼，`ul` 为 `un lock` 简拼，使用上是等效的。

# 特性说明

**智能防火墙检测**

- 脚本会自动检测系统的防火墙类型并选择最佳配置
- 优先级：firewalld > nftables > iptables
- 如果没有防火墙，会自动安装 iptables

**日志系统适配**

- 自动检测是否使用 journald（新系统）或传统日志文件
- 在 journald-only 系统上自动使用 `backend = systemd`
- 兼容 rsyslog、syslog-ng 等传统日志服务

**输入验证**

- 安装时会验证输入的失败次数和封禁时长必须为数字
- 非法输入会提示重新输入

**Windows 工作方式**

- 通过 `OpenSSH/Operational` 事件日志识别 SSH 失败登录
- 通过 Windows Defender Firewall 自动创建和移除封禁规则
- 通过计划任务定时扫描并清理过期封禁

# 日志

`2026-04-09` : Windows 支持

- 新增 `fail2ban.ps1`，支持 Windows OpenSSH 登录失败检测
- 使用 Windows Firewall 执行 IP 封禁 / 解封
- 使用计划任务实现持续监控
- 增加 `install-win.bat` / `uninstall-win.bat` 本地一键安装与卸载
- 增加 GitHub 远程一键安装与卸载命令

`2026-01-21` : 重大更新

- 支持现代 Linux 发行版（Rocky/AlmaLinux/Fedora 等）
- 智能检测防火墙类型（firewalld/nftables/iptables）
- 支持 systemd journal 日志系统
- 自动适配服务管理器（systemd/sysvinit）
- 自动选择包管理器（dnf/yum/apt）
- 增加输入验证和错误处理
- 改进用户体验和提示信息

`2018-02-15` : 创建

# 更多

https://www.fail2ban.org

https://linux.cn/article-5067-1.html
