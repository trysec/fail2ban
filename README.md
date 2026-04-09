# 简介

fail2ban 一键安装 / 卸载脚本。

支持自动检测系统环境，并配置合适的防火墙和日志方案。

# 环境

支持的操作系统：

- **RHEL 系列**: CentOS 7/8/9, RHEL 7/8/9, Rocky Linux 8/9, AlmaLinux 8/9, Fedora
- **Debian 系列**: Debian 9/10/11/12, Ubuntu 18.04/20.04/22.04/24.04
- **Windows**: Windows 10, Windows 11, Windows Server 2016/2019/2022/2025（PowerShell 版，主要保护 RDP，依赖 Windows Defender Firewall）

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
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path $env:TEMP 'install_latest.ps1'
(New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/trysec/fail2ban/master/install_latest.ps1', $tmp)
powershell -NoProfile -ExecutionPolicy Bypass -File $tmp
```

Windows GitHub 一键卸载：

```powershell
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path $env:TEMP 'install_latest.ps1'
(New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/trysec/fail2ban/master/install_latest.ps1', $tmp)
powershell -NoProfile -ExecutionPolicy Bypass -File $tmp -Uninstall
```

Windows GitHub 高级安装示例：

```powershell
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path $env:TEMP 'install_latest.ps1'
(New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/trysec/fail2ban/master/install_latest.ps1', $tmp)
powershell -NoProfile -ExecutionPolicy Bypass -File $tmp -Threshold 8 -BanHours 24 -FindTimeMinutes 30 -MinimumFailureIntervalSeconds 3 -IgnoreIPs '127.0.0.1,::1,10.0.0.5'
```

Windows CMD 一键安装：

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $tmp=Join-Path $env:TEMP 'install_latest.ps1'; (New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/trysec/fail2ban/master/install_latest.ps1',$tmp); powershell -NoProfile -ExecutionPolicy Bypass -File $tmp"
```

Windows CMD 一键卸载：

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $tmp=Join-Path $env:TEMP 'install_latest.ps1'; (New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/trysec/fail2ban/master/install_latest.ps1',$tmp); powershell -NoProfile -ExecutionPolicy Bypass -File $tmp -Uninstall"
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

Windows 查看白名单 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 whitelist list`

Windows 添加白名单 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 whitelist add ip`

Windows 删除白名单 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 whitelist remove ip`

Windows 查看配置 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 config show`

Windows 修改配置 : `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 config set threshold 8`

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

- 通过 `Security` 日志中的 `4625` 失败登录事件识别 RDP 爆破
- 仅统计 `LogonType = 10` 的远程桌面失败登录
- 通过 Windows Defender Firewall 自动创建和移除封禁规则
- 通过计划任务定时扫描并清理过期封禁
- 支持自定义忽略 IP 列表
- 通过近期失败记录持久化和最小失败间隔去重，减少重复计数

**Windows 支持范围**

- 保守支持：Windows 10、Windows 11、Windows Server 2016、Windows Server 2019、Windows Server 2022、Windows Server 2025
- 依赖组件：PowerShell、`Get-WinEvent`、Windows Defender Firewall、计划任务、`Security` 日志中的 `4625` 事件
- 更早版本没有在当前脚本里声明支持，即使理论上部分组件存在，也不建议直接视为兼容

**Windows 测试矩阵**

| 版本 | 支持状态 | 主要用途 | 建议验证项 |
| --- | --- | --- | --- |
| Windows 10 | 支持 | 桌面 / 跳板机 | `4625` 事件、Firewall 规则、计划任务 |
| Windows 11 | 支持 | 桌面 / 跳板机 | `4625` 事件、Firewall 规则、计划任务 |
| Windows Server 2016 | 支持 | 服务器 / RDP 防护 | `4625` 事件、TermService、Firewall 规则、计划任务 |
| Windows Server 2019 | 支持 | 服务器 / RDP 防护 | `4625` 事件、TermService、Firewall 规则、计划任务 |
| Windows Server 2022 | 支持 | 服务器 / RDP 防护 | `4625` 事件、TermService、Firewall 规则、计划任务 |
| Windows Server 2025 | 支持 | 服务器 / RDP 防护 | `4625` 事件、TermService、Firewall 规则、计划任务 |

**Windows 最小验收步骤**

1. 安装后执行 `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 status`，确认计划任务存在且配置已写入。
2. 执行 `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20`，确认系统确实能看到失败登录事件。
3. 进行一次可控的 RDP 失败登录测试，确认来源 IP 被记录并在达到阈值后进入封禁。
4. 执行 `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 blocklist`，确认被封 IP 可见。
5. 执行 `Get-NetFirewallRule -Group 'Fail2Ban Windows'`，确认对应防火墙规则已创建。
6. 执行 `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 unlock <ip>`，确认防火墙规则和状态记录都能移除。
7. 执行 `powershell -ExecutionPolicy Bypass -File .\fail2ban.ps1 whitelist list` 和 `config show`，确认白名单和配置管理命令正常工作。

# 日志

`2026-04-09` : Windows 支持

- 新增 `fail2ban.ps1`，支持 Windows RDP 登录失败检测
- 使用 Windows Firewall 执行 IP 封禁 / 解封
- 使用计划任务实现持续监控
- 增加 `install-win.bat` / `uninstall-win.bat` 本地一键安装与卸载
- 增加 GitHub 远程一键安装与卸载命令
- 新增 `install_latest.ps1`，支持 IPBan 风格远程一键安装
- 新增忽略 IP 配置与最小失败间隔去重
- 新增 `whitelist` / `config` 命令，支持在线调整白名单和配置

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
