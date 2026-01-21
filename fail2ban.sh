#!/bin/bash

# 检测操作系统
CHECK_OS(){
    # 优先使用 /etc/os-release，这是现代Linux的标准
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID

        case "$OS" in
            centos|rhel|rocky|almalinux|fedora)
                release="centos"
                ;;
            debian)
                release="debian"
                ;;
            ubuntu)
                release="ubuntu"
                ;;
            *)
                # 兼容性回退检测
                if [[ -f /etc/redhat-release ]]; then
                    release="centos"
                elif grep -q -i debian /etc/issue 2>/dev/null; then
                    release="debian"
                elif grep -q -i ubuntu /etc/issue 2>/dev/null; then
                    release="ubuntu"
                else
                    release="unknown"
                fi
                ;;
        esac
    else
        # 旧版本Linux回退检测方法
        if [[ -f /etc/redhat-release ]]; then
            release="centos"
        elif cat /etc/issue 2>/dev/null | grep -q -E -i "debian"; then
            release="debian"
        elif cat /etc/issue 2>/dev/null | grep -q -E -i "ubuntu"; then
            release="ubuntu"
        elif cat /etc/issue 2>/dev/null | grep -q -E -i "centos|red hat|redhat"; then
            release="centos"
        elif cat /proc/version 2>/dev/null | grep -q -E -i "debian"; then
            release="debian"
        elif cat /proc/version 2>/dev/null | grep -q -E -i "ubuntu"; then
            release="ubuntu"
        elif cat /proc/version 2>/dev/null | grep -q -E -i "centos|red hat|redhat"; then
            release="centos"
        else
            release="unknown"
        fi
    fi
}

# 检测服务管理器类型
CHECK_SERVICE_MANAGER(){
    if command -v systemctl &> /dev/null && systemctl --version &> /dev/null; then
        SERVICE_MANAGER="systemd"
    else
        SERVICE_MANAGER="sysvinit"
    fi
}

# 获取SSH服务名称
GET_SSH_SERVICE_NAME(){
    if systemctl list-unit-files 2>/dev/null | grep -q "^sshd.service"; then
        SSH_SERVICE="sshd"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^ssh.service"; then
        SSH_SERVICE="ssh"
    elif [[ -f /etc/init.d/sshd ]]; then
        SSH_SERVICE="sshd"
    elif [[ -f /etc/init.d/ssh ]]; then
        SSH_SERVICE="ssh"
    else
        # 根据发行版设置默认值
        case "${release}" in
            centos)
                SSH_SERVICE="sshd"
                ;;
            debian|ubuntu)
                SSH_SERVICE="ssh"
                ;;
            *)
                SSH_SERVICE="sshd"
                ;;
        esac
    fi
}

# 检测防火墙类型
DETECT_FIREWALL(){
    # 优先级：firewalld > nftables > iptables
    if command -v firewall-cmd &> /dev/null && systemctl is-active firewalld &> /dev/null; then
        FIREWALL_TYPE="firewalld"
        FAIL2BAN_ACTION="firewallcmd-ipset"
    elif command -v nft &> /dev/null && (nft list tables 2>/dev/null | grep -q .) ; then
        FIREWALL_TYPE="nftables"
        FAIL2BAN_ACTION="nftables-multiport"
    elif command -v iptables &> /dev/null; then
        FIREWALL_TYPE="iptables"
        FAIL2BAN_ACTION="iptables[name=SSH, port=ssh, protocol=tcp]"
    else
        # 如果都没有，尝试安装 iptables 作为回退
        FIREWALL_TYPE="iptables"
        FAIL2BAN_ACTION="iptables[name=SSH, port=ssh, protocol=tcp]"
        echo "警告: 未检测到防火墙，将使用 iptables"
    fi
}

# 检测日志系统类型
DETECT_LOG_BACKEND(){
    local log_file=$1

    # 检查传统日志文件是否存在且有内容
    if [[ -f "$log_file" ]] && [[ -s "$log_file" ]]; then
        # 文件存在且不为空，使用传统日志
        USE_SYSTEMD_BACKEND=false
        LOG_BACKEND="auto"
    elif systemctl is-active rsyslog &> /dev/null || systemctl is-active syslog-ng &> /dev/null; then
        # rsyslog/syslog-ng 在运行，但日志文件可能还未创建
        USE_SYSTEMD_BACKEND=false
        LOG_BACKEND="auto"
    elif command -v journalctl &> /dev/null && systemctl --version &> /dev/null; then
        # 只有 systemd journal，没有传统日志
        USE_SYSTEMD_BACKEND=true
        LOG_BACKEND="systemd"
    else
        # 回退到自动检测
        USE_SYSTEMD_BACKEND=false
        LOG_BACKEND="auto"
    fi
}

# 启动/停止/重启服务的通用函数
SERVICE_CONTROL(){
    local service_name=$1
    local action=$2

    CHECK_SERVICE_MANAGER

    case "$action" in
        start|stop|restart|status)
            if [[ "$SERVICE_MANAGER" == "systemd" ]]; then
                systemctl $action $service_name
            else
                service $service_name $action
            fi
            ;;
        enable)
            if [[ "$SERVICE_MANAGER" == "systemd" ]]; then
                systemctl enable $service_name
            else
                if command -v chkconfig &> /dev/null; then
                    chkconfig $service_name on
                elif command -v update-rc.d &> /dev/null; then
                    update-rc.d $service_name defaults
                fi
            fi
            ;;
    esac
}

GET_SETTING_FAIL2BAN_INFO(){
    # 获取并验证失败次数
    while true; do
        read -p "允许SSH登陆失败次数,默认10:" BLOCKING_THRESHOLD
        if [[ -z "${BLOCKING_THRESHOLD}" ]]; then
            BLOCKING_THRESHOLD='10'
            break
        elif [[ "${BLOCKING_THRESHOLD}" =~ ^[0-9]+$ ]]; then
            break
        else
            echo "错误: 请输入有效的数字"
        fi
    done

    # 获取并验证封禁时长
    while true; do
        read -p "SSH登陆失败次数超过${BLOCKING_THRESHOLD}次时,封禁时长(h),默认8760:" BLOCKING_TIME_H
        if [[ -z "${BLOCKING_TIME_H}" ]]; then
            BLOCKING_TIME_H='8760'
            break
        elif [[ "${BLOCKING_TIME_H}" =~ ^[0-9]+$ ]]; then
            break
        else
            echo "错误: 请输入有效的数字"
        fi
    done

    # 使用bash算术运算，比expr更高效
    BLOCKING_TIME_S=$((BLOCKING_TIME_H * 3600))
}

INSTALL_FAIL2BAN(){
    if [[ -e /etc/fail2ban/jail.local ]]; then
        echo "fail2ban已经安装了."
        exit 0
    fi

    CHECK_OS

    if [[ "$release" == "unknown" ]]; then
        echo "不支持的操作系统。请使用CentOS/RHEL/Rocky/AlmaLinux/Debian/Ubuntu系统."
        exit 1
    fi

    GET_SETTING_FAIL2BAN_INFO

    case "${release}" in
        centos)
            # 检测包管理器
            if command -v dnf &> /dev/null; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi

            echo "正在安装fail2ban (使用 $PKG_MANAGER)..."
            $PKG_MANAGER -y install epel-release
            $PKG_MANAGER -y install fail2ban
            ;;
        debian|ubuntu)
            echo "正在安装fail2ban..."
            apt-get update
            apt-get -y install fail2ban
            ;;
        *)
            echo "请使用CentOS/RHEL/Rocky/AlmaLinux/Debian/Ubuntu系统."
            exit 1
            ;;
    esac
}

REMOVE_FAIL2BAN(){
    if [[ ! -e /etc/fail2ban/jail.local ]]; then
        echo "fail2ban尚未安装."
        exit 0
    fi

    CHECK_OS
    SERVICE_CONTROL fail2ban stop

    case "${release}" in
        centos)
            if command -v dnf &> /dev/null; then
                dnf -y remove fail2ban
            else
                yum -y remove fail2ban
            fi
            ;;
        debian|ubuntu)
            apt-get -y remove --purge fail2ban
            apt-get -y autoremove
            ;;
    esac

    rm -rf /etc/fail2ban/jail.local
    echo "fail2ban已卸载."
}

SETTING_FAIL2BAN(){
    CHECK_OS
    GET_SSH_SERVICE_NAME
    DETECT_FIREWALL

    # 根据发行版确定默认日志文件
    case "${release}" in
        centos)
            DEFAULT_LOG_FILE="/var/log/secure"
            ;;
        debian|ubuntu)
            DEFAULT_LOG_FILE="/var/log/auth.log"
            ;;
    esac

    # 检测日志后端
    DETECT_LOG_BACKEND "$DEFAULT_LOG_FILE"

    echo "检测到防火墙类型: $FIREWALL_TYPE"
    echo "检测到日志后端: $LOG_BACKEND"

    # 生成配置
    if [[ "$USE_SYSTEMD_BACKEND" == true ]]; then
        # 使用 systemd journal
        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1
bantime = 86400
maxretry = 3
findtime = 1800

[sshd]
enabled = true
filter = sshd
backend = systemd
maxretry = ${BLOCKING_THRESHOLD}
findtime = 3600
bantime = ${BLOCKING_TIME_S}
action = ${FAIL2BAN_ACTION}
EOF
    else
        # 使用传统日志文件
        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1
bantime = 86400
maxretry = 3
findtime = 1800

[sshd]
enabled = true
filter = sshd
logpath = ${DEFAULT_LOG_FILE}
maxretry = ${BLOCKING_THRESHOLD}
findtime = 3600
bantime = ${BLOCKING_TIME_S}
action = ${FAIL2BAN_ACTION}
EOF
    fi

    SERVICE_CONTROL fail2ban restart
    SERVICE_CONTROL fail2ban enable
    SERVICE_CONTROL $SSH_SERVICE restart

    echo "fail2ban配置完成."
    echo "使用的防火墙: $FIREWALL_TYPE"
    echo "使用的日志后端: $LOG_BACKEND"
}

VIEW_RUN_LOG(){
    CHECK_OS

    case "${release}" in
        centos)
            if [[ -f /var/log/secure ]]; then
                tail -f /var/log/secure
            else
                # 使用journalctl查看systemd日志
                echo "使用journalctl查看日志..."
                journalctl -u sshd -f
            fi
            ;;
        debian|ubuntu)
            if [[ -f /var/log/auth.log ]]; then
                tail -f /var/log/auth.log
            else
                echo "使用journalctl查看日志..."
                journalctl -u ssh -f
            fi
            ;;
    esac
}

case "${1}" in
    install)
        INSTALL_FAIL2BAN
        SETTING_FAIL2BAN
        ;;
    uninstall)
        REMOVE_FAIL2BAN
        ;;
    status)
        echo -e "\033[41;37m【进程】\033[0m"
        ps aux | grep fail2ban | grep -v grep
        echo
        echo -e "\033[41;37m【状态】\033[0m"
        fail2ban-client ping 2>/dev/null || echo "fail2ban未运行"
        echo
        echo -e "\033[41;37m【Service】\033[0m"
        SERVICE_CONTROL fail2ban status
        ;;
    blocklist|bl)
        if [[ -e /etc/fail2ban/jail.local ]]; then
            fail2ban-client status sshd
        else
            echo "fail2ban尚未安装."
            exit 1
        fi
        ;;
    unlock|ul)
        if [[ ! -e /etc/fail2ban/jail.local ]]; then
            echo "fail2ban尚未安装."
            exit 1
        fi

        if [[ -z "${2}" ]]; then
            read -p "请输入需要解封的IP:" UNLOCK_IP
            if [[ -z "${UNLOCK_IP}" ]]; then
                echo "不允许空值,请重试."
                exit 1
            fi
        else
            UNLOCK_IP="${2}"
        fi

        fail2ban-client set sshd unbanip ${UNLOCK_IP}
        echo "IP ${UNLOCK_IP} 已解封."
        ;;
    more)
        echo "【参考文章】
https://www.fail2ban.org
https://linux.cn/article-5067-1.html

【更多命令】
fail2ban-client -h"
        ;;
    runlog)
        VIEW_RUN_LOG
        ;;
    start)
        SERVICE_CONTROL fail2ban start
        ;;
    stop)
        SERVICE_CONTROL fail2ban stop
        ;;
    restart)
        SERVICE_CONTROL fail2ban restart
        ;;
    *)
        echo "bash fail2ban.sh {install|uninstall|runlog|more}"
        echo "bash fail2ban.sh {start|stop|restart|status}"
        echo "bash fail2ban.sh {blocklist|unlock}"
        ;;
esac

#END
