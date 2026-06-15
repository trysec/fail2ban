#!/bin/bash

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

ASSERT_ROOT(){
    if [[ $EUID -ne 0 ]]; then
        echo "错误: 此操作需要 root 权限，请使用 sudo 运行。"
        exit 1
    fi
}

CHECK_WINDOWS_SHELL(){
    local uname_s
    uname_s="$(uname -s 2>/dev/null)"

    case "${uname_s}" in
        MINGW*|MSYS*|CYGWIN*)
            echo "Detected Windows shell environment."
            echo "Please use the PowerShell version instead:"
            echo "powershell -ExecutionPolicy Bypass -File .\\fail2ban.ps1 {install|uninstall|runlog|more}"
            echo "powershell -ExecutionPolicy Bypass -File .\\fail2ban.ps1 {start|stop|restart|status}"
            echo "powershell -ExecutionPolicy Bypass -File .\\fail2ban.ps1 {blocklist|unlock} [ip]"
            exit 1
            ;;
    esac
}

CHECK_WINDOWS_SHELL

JAIL_NAME="sshd"
FAIL2BAN_SOURCE_VERSION="1.1.0"
FAIL2BAN_SOURCE_URL="https://github.com/fail2ban/fail2ban/archive/refs/tags/${FAIL2BAN_SOURCE_VERSION}.tar.gz"

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

# 检查 fail2ban action 文件是否存在
CHECK_FAIL2BAN_ACTION(){
    local action_name=$1
    local action_file="${action_name}.conf"

    # 按优先级检查所有可能的路径
    local search_paths=(
        "/etc/fail2ban/action.d"
        "/usr/lib/fail2ban/action.d"
        "/usr/lib64/fail2ban/action.d"
        "/usr/share/fail2ban/action.d"
        "/usr/local/share/fail2ban/action.d"
    )

    for path in "${search_paths[@]}"; do
        if [[ -f "${path}/${action_file}" ]]; then
            return 0  # 找到了
        fi
    done

    return 1  # 未找到
}

# 检测并安装防火墙
DETECT_FIREWALL(){
    # 优先级：firewalld > nftables > iptables

    # 检查 firewalld
    if command -v firewall-cmd &> /dev/null; then
        if systemctl is-active firewalld &> /dev/null; then
            # 检查 firewallcmd-ipset action 是否存在
            if CHECK_FAIL2BAN_ACTION "firewallcmd-ipset"; then
                FIREWALL_TYPE="firewalld"
                FAIL2BAN_ACTION="firewallcmd-ipset"
                return
            else
                echo "警告: firewalld 运行中但 fail2ban 缺少 firewallcmd-ipset action"
                echo "      将尝试使用其他防火墙方案"
            fi
        else
            echo "提示: 检测到 firewalld 已安装但未运行"
            echo "      如需使用 firewalld，请运行: systemctl start firewalld && systemctl enable firewalld"
        fi
    fi

    # 检查 nftables
    if command -v nft &> /dev/null; then
        # 检查 fail2ban 是否支持 nftables action
        if CHECK_FAIL2BAN_ACTION "nftables-multiport"; then
            FIREWALL_TYPE="nftables"
            FAIL2BAN_ACTION="nftables-multiport"
            return
        else
            echo "警告: nft 命令存在但 fail2ban 缺少 nftables-multiport action"
            echo "      将尝试使用其他防火墙方案"
        fi
    fi

    # 检查 iptables
    if command -v iptables &> /dev/null; then
        FIREWALL_TYPE="iptables"
        FAIL2BAN_ACTION="iptables[name=SSH, port=ssh, protocol=tcp]"
        return
    fi

    # 没有任何可用的防火墙工具，尝试安装 iptables
    echo "警告: 未检测到可用的防火墙工具 (firewalld/nftables/iptables)"
    if IS_EL9_OR_NEWER; then
        echo "错误: EL9 小规格主机上不自动安装 iptables，避免 dnf 卡住。请先安装 firewalld/nftables/iptables 后重试。"
        exit 1
    fi

    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        echo "错误: Debian/Ubuntu 小规格主机上不自动安装 iptables，避免 apt/dpkg/man-db 卡住。"
        echo "      请先安装或启用 firewalld/nftables/iptables 后重试。"
        exit 1
    fi

    echo "正在尝试安装 iptables..."

    CHECK_OS
    case "${release}" in
        centos)
            if command -v dnf &> /dev/null; then
                RUN_DNF -y install iptables iptables-services
            else
                RUN_YUM -y install iptables iptables-services
            fi
            ;;
        debian|ubuntu)
            RUN_APT_GET -y install iptables
            ;;
    esac

    # 再次检查是否安装成功
    if command -v iptables &> /dev/null; then
        FIREWALL_TYPE="iptables"
        FAIL2BAN_ACTION="iptables[name=SSH, port=ssh, protocol=tcp]"
        echo "iptables 安装成功"
    else
        echo "错误: 无法安装防火墙工具，fail2ban 需要防火墙才能工作"
        exit 1
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

ENSURE_SYSTEMD_BACKEND_SUPPORT(){
    if python3 -c 'import systemd.journal' >/dev/null 2>&1; then
        return 0
    fi

    echo "检测到 systemd journal 后端需要 python3-systemd。"
    case "${release}" in
        centos)
            if IS_EL9_OR_NEWER; then
                echo "错误: EL9 上缺少 python3-systemd，脚本不会自动调用 dnf 安装以避免卡住。"
                echo "      可先安装 rsyslog 生成 /var/log/secure，或手动安装 python3-systemd 后重试。"
                return 1
            fi

            echo "正在安装 python3-systemd..."
            if command -v dnf &> /dev/null; then
                RUN_DNF -y install python3-systemd
            else
                RUN_YUM -y install python3-systemd
            fi
            ;;
        debian|ubuntu)
            echo "错误: Debian/Ubuntu 上缺少 python3-systemd，脚本不会自动调用 apt 安装以避免 apt/dpkg/man-db 卡住。"
            echo "      可先安装 rsyslog 生成 /var/log/auth.log，或手动安装 python3-systemd 后重试。"
            return 1
            ;;
        *)
            return 1
            ;;
    esac

    python3 -c 'import systemd.journal' >/dev/null 2>&1
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

DISABLE_FAIL2BAN_AUTO_START(){
    CHECK_SERVICE_MANAGER

    if [[ "$SERVICE_MANAGER" == "systemd" ]]; then
        systemctl disable fail2ban >/dev/null 2>&1 || true
    else
        if command -v chkconfig &> /dev/null; then
            chkconfig fail2ban off >/dev/null 2>&1 || true
        elif command -v update-rc.d &> /dev/null; then
            update-rc.d fail2ban disable >/dev/null 2>&1 || true
        fi
    fi
}

FAIL2BAN_SERVICE_EXISTS(){
    CHECK_SERVICE_MANAGER

    if [[ "$SERVICE_MANAGER" == "systemd" ]]; then
        systemctl cat fail2ban >/dev/null 2>&1
    else
        [[ -x /etc/init.d/fail2ban ]]
    fi
}

INSTALL_FAIL2BAN_FROM_SOURCE(){
    local work_dir="/tmp/fail2ban-install.$$"
    local archive_path="${work_dir}/fail2ban.tar.gz"
    local source_dir="${work_dir}/fail2ban-${FAIL2BAN_SOURCE_VERSION}"
    local install_base="/usr/local/lib/fail2ban"
    local install_record="/etc/fail2ban/source-install-files.txt"
    local fail2ban_server_bin=""
    local fail2ban_client_bin=""

    CHECK_SERVICE_MANAGER
    if [[ "$SERVICE_MANAGER" != "systemd" ]]; then
        echo "错误: 源码安装需要 systemd 服务管理器。"
        return 1
    fi

    echo "正在通过源码包安装 fail2ban ${FAIL2BAN_SOURCE_VERSION}，跳过发行版包管理器元数据和触发器..."
    mkdir -p "$work_dir" || return 1

    if command -v curl &> /dev/null; then
        RUN_LOW_PRIORITY curl -L --fail --connect-timeout 15 --max-time 180 -o "$archive_path" "$FAIL2BAN_SOURCE_URL" || {
            rm -rf "$work_dir"
            return 1
        }
    elif command -v wget &> /dev/null; then
        RUN_LOW_PRIORITY wget -T 15 -O "$archive_path" "$FAIL2BAN_SOURCE_URL" || {
            rm -rf "$work_dir"
            return 1
        }
    else
        echo "错误: 未找到 curl 或 wget，无法下载 fail2ban 源码包。"
        rm -rf "$work_dir"
        return 1
    fi

    tar -xzf "$archive_path" -C "$work_dir" || {
        rm -rf "$work_dir"
        return 1
    }

    if [[ ! -f "${source_dir}/setup.py" || \
        ! -f "${source_dir}/fail2ban/__init__.py" || \
        ! -x "${source_dir}/bin/fail2ban-server" ]]; then
        echo "错误: fail2ban 源码包解压后目录结构异常，取消安装。"
        rm -rf "$work_dir"
        return 1
    fi

    if ! command -v python3 &> /dev/null; then
        echo "错误: 未找到 python3，无法安装 fail2ban。"
        rm -rf "$work_dir"
        return 1
    fi

    mkdir -p /etc/fail2ban /run/fail2ban /var/lib/fail2ban /usr/local/bin
    rm -rf "$install_base"
    mkdir -p "$install_base" || {
        rm -rf "$work_dir"
        return 1
    }

    cp -R "${source_dir}/fail2ban" "$install_base/" || {
        rm -rf "$work_dir" "$install_base"
        return 1
    }
    cp -R "${source_dir}/bin" "$install_base/" || {
        rm -rf "$work_dir" "$install_base"
        return 1
    }
    cp -R "${source_dir}/config/." /etc/fail2ban/ || {
        rm -rf "$work_dir" "$install_base"
        return 1
    }
    chmod +x "${install_base}/bin/fail2ban-client" \
        "${install_base}/bin/fail2ban-server" \
        "${install_base}/bin/fail2ban-regex" 2>/dev/null || true

    PYTHONPATH="$install_base" python3 - <<'PY' >/dev/null 2>&1 || {
import fail2ban.client.fail2banclient
import fail2ban.client.fail2banserver
PY
        echo "错误: fail2ban Python 模块验证失败。"
        rm -rf "$work_dir" "$install_base"
        return 1
    }

    cat > /usr/local/bin/fail2ban-client <<EOF
#!/bin/sh
export PYTHONPATH="${install_base}\${PYTHONPATH:+:\$PYTHONPATH}"
exec /usr/bin/env python3 "${install_base}/bin/fail2ban-client" "\$@"
EOF
    cat > /usr/local/bin/fail2ban-server <<EOF
#!/bin/sh
export PYTHONPATH="${install_base}\${PYTHONPATH:+:\$PYTHONPATH}"
exec /usr/bin/env python3 "${install_base}/bin/fail2ban-server" "\$@"
EOF
    cat > /usr/local/bin/fail2ban-regex <<EOF
#!/bin/sh
export PYTHONPATH="${install_base}\${PYTHONPATH:+:\$PYTHONPATH}"
exec /usr/bin/env python3 "${install_base}/bin/fail2ban-regex" "\$@"
EOF
    chmod +x /usr/local/bin/fail2ban-client \
        /usr/local/bin/fail2ban-server \
        /usr/local/bin/fail2ban-regex
    ln -sf "$(command -v python3)" /usr/local/bin/fail2ban-python

    fail2ban_server_bin="$(command -v fail2ban-server 2>/dev/null || true)"
    fail2ban_client_bin="$(command -v fail2ban-client 2>/dev/null || true)"

    if [[ -z "$fail2ban_server_bin" || -z "$fail2ban_client_bin" ]]; then
        echo "错误: fail2ban 源码安装后未找到 fail2ban-server 或 fail2ban-client。"
        rm -rf "$work_dir"
        return 1
    fi

    {
        printf '%s\n' \
            "/usr/local/bin/fail2ban-client" \
            "/usr/local/bin/fail2ban-server" \
            "/usr/local/bin/fail2ban-regex" \
            "/usr/local/bin/fail2ban-python"
        find "$install_base" -type f -print 2>/dev/null
        find /etc/fail2ban -type f \
            ! -name 'jail.local' \
            ! -name 'install-method' \
            ! -name 'source-install-files.txt' \
            -print 2>/dev/null
    } > "$install_record"
    echo "source" > /etc/fail2ban/install-method

    cat > /etc/systemd/system/fail2ban.service <<EOF
[Unit]
Description=Fail2Ban Service
Documentation=man:fail2ban(1)
After=network.target iptables.service firewalld.service
PartOf=firewalld.service

[Service]
Type=simple
ExecStart=${fail2ban_server_bin} -xf start
ExecReload=${fail2ban_client_bin} reload
ExecStop=${fail2ban_client_bin} stop
PIDFile=/run/fail2ban/fail2ban.pid
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null || true

    rm -rf "$work_dir"
    return 0
}

ASSERT_FAIL2BAN_INSTALLED(){
    local ok=true

    if ! command -v fail2ban-client &> /dev/null; then
        echo "错误: 未找到 fail2ban-client，fail2ban 未正确安装。"
        ok=false
    fi

    if ! command -v fail2ban-server &> /dev/null; then
        echo "错误: 未找到 fail2ban-server，fail2ban 服务端组件未正确安装。"
        ok=false
    fi

    if ! FAIL2BAN_SERVICE_EXISTS; then
        echo "错误: 未找到 fail2ban.service，fail2ban 服务未正确安装。"
        ok=false
    fi

    if [[ "$ok" != true ]]; then
        echo "请检查 fail2ban 安装输出、Python 环境和系统服务文件，然后重新执行: bash fail2ban.sh install"
        return 1
    fi

    mkdir -p /etc/fail2ban
    return 0
}

GET_EL_MAJOR_VERSION(){
    local major="${VER%%.*}"

    if ! [[ "$major" =~ ^[0-9]+$ ]] && command -v rpm &> /dev/null; then
        major="$(rpm -E '%{rhel}' 2>/dev/null)"
    fi

    echo "$major"
}

IS_EL9_OR_NEWER(){
    local major

    case "$OS" in
        centos|rhel|rocky|almalinux)
            ;;
        *)
            return 1
            ;;
    esac

    major="$(GET_EL_MAJOR_VERSION)"
    [[ "$major" =~ ^[0-9]+$ ]] && (( major >= 9 ))
}

RUN_DNF(){
    local args=()

    if IS_EL9_OR_NEWER; then
        args+=(
            "--disablerepo=powertools"
            "--disablerepo=PowerTools"
            "--disablerepo=*powertools*"
            "--disablerepo=*PowerTools*"
            "--disablerepo=epel"
            "--disablerepo=epel-next"
            "--disablerepo=*epel*"
            "--setopt=timeout=15"
            "--setopt=minrate=1000"
            "--setopt=max_parallel_downloads=1"
        )
    fi

    RUN_LOW_PRIORITY dnf "${args[@]}" "$@"
}

RUN_YUM(){
    local args=()

    if IS_EL9_OR_NEWER; then
        args+=(
            "--disablerepo=powertools"
            "--disablerepo=PowerTools"
            "--disablerepo=*powertools*"
            "--disablerepo=*PowerTools*"
            "--disablerepo=epel"
            "--disablerepo=epel-next"
            "--disablerepo=*epel*"
            "--setopt=timeout=15"
            "--setopt=minrate=1000"
        )
    fi

    RUN_LOW_PRIORITY yum "${args[@]}" "$@"
}

RUN_APT_GET(){
    RUN_LOW_PRIORITY env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
        apt-get \
        -o Acquire::http::Timeout=15 \
        -o Acquire::https::Timeout=15 \
        -o Acquire::Retries=1 \
        "$@"
}

RUN_LOW_PRIORITY(){
    local cmd=("$@")

    if command -v ionice &> /dev/null; then
        cmd=(ionice -c3 "${cmd[@]}")
    fi

    if command -v nice &> /dev/null; then
        cmd=(nice -n 19 "${cmd[@]}")
    fi

    if command -v timeout &> /dev/null; then
        timeout 900 "${cmd[@]}"
    else
        "${cmd[@]}"
    fi
}

RUN_EL_PKG_MANAGER(){
    local pkg_manager=$1
    shift

    if [[ "$pkg_manager" == "dnf" ]]; then
        RUN_DNF "$@"
    else
        RUN_YUM "$@"
    fi
}

DISABLE_INCOMPATIBLE_EL_REPOS(){
    if ! IS_EL9_OR_NEWER; then
        return 0
    fi

    if compgen -G "/etc/yum.repos.d/*.repo" >/dev/null 2>&1; then
        sed -i '/^\[PowerTools\]/,/^\[/{s/^enabled=.*/enabled=0/}' /etc/yum.repos.d/*.repo 2>/dev/null || true
        sed -i '/^\[powertools\]/,/^\[/{s/^enabled=.*/enabled=0/}' /etc/yum.repos.d/*.repo 2>/dev/null || true
    fi
}

ENABLE_CRB_REPO(){
    if ! IS_EL9_OR_NEWER; then
        return 1
    fi

    if compgen -G "/etc/yum.repos.d/*.repo" >/dev/null 2>&1; then
        sed -i '/^\[crb\]/,/^\[/{s/^enabled=.*/enabled=1/}' /etc/yum.repos.d/*.repo 2>/dev/null || true
        sed -i '/^\[CRB\]/,/^\[/{s/^enabled=.*/enabled=1/}' /etc/yum.repos.d/*.repo 2>/dev/null || true
    fi

    return 0
}

CLEAN_EL_METADATA(){
    local pkg_manager=$1

    if [[ "$pkg_manager" == "dnf" ]]; then
        RUN_DNF clean metadata >/dev/null 2>&1 || true
    else
        RUN_YUM clean metadata >/dev/null 2>&1 || true
    fi
}

ENABLE_EL_REPOS(){
    local pkg_manager=$1
    local major

    if [[ "$OS" == "fedora" ]]; then
        return 0
    fi

    major="$(GET_EL_MAJOR_VERSION)"
    DISABLE_INCOMPATIBLE_EL_REPOS
    CLEAN_EL_METADATA "$pkg_manager"

    echo "正在启用 EPEL 仓库..."
    if ! rpm -q epel-release >/dev/null 2>&1; then
        if ! RUN_EL_PKG_MANAGER "$pkg_manager" -y install epel-release; then
            if [[ "$major" =~ ^[0-9]+$ ]]; then
                RUN_EL_PKG_MANAGER "$pkg_manager" -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${major}.noarch.rpm" || return 1
            else
                return 1
            fi
        fi
    fi

    if [[ "$pkg_manager" == "dnf" ]]; then
        if IS_EL9_OR_NEWER; then
            ENABLE_CRB_REPO
        fi
    fi

    return 0
}

INSTALL_FAIL2BAN_PACKAGE_EL(){
    local pkg_manager=$1

    if IS_EL9_OR_NEWER; then
        CHECK_SOURCE_INSTALL_PREREQS || return 1
        INSTALL_FAIL2BAN_FROM_SOURCE
        return $?
    fi

    if RUN_EL_PKG_MANAGER "$pkg_manager" -y install fail2ban; then
        return 0
    fi

    RUN_EL_PKG_MANAGER "$pkg_manager" -y install fail2ban-server fail2ban-systemd
}

CHECK_SOURCE_INSTALL_PREREQS(){
    local missing=()

    command -v python3 &> /dev/null || missing+=("python3")

    command -v tar &> /dev/null || missing+=("tar")
    command -v gzip &> /dev/null || missing+=("gzip")

    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        missing+=("curl或wget")
    fi

    if (( ${#missing[@]} == 0 )); then
        return 0
    fi

    echo "错误: 源码安装缺少依赖: ${missing[*]}"
    case "${release}" in
        centos)
            echo "      为避免小规格 EL9 主机再次触发 dnf/yum 卡顿，脚本不会自动安装这些依赖。"
            ;;
        debian|ubuntu)
            echo "      为避免小规格 Debian/Ubuntu 主机再次触发 apt/dpkg/man-db 卡顿，脚本不会自动安装这些依赖。"
            ;;
    esac
    echo "      请先手动安装缺失依赖后重试: bash fail2ban.sh install"
    return 1
}

INSTALL_FAIL2BAN_PACKAGE_DEB(){
    CHECK_SERVICE_MANAGER

    if [[ "$SERVICE_MANAGER" != "systemd" ]]; then
        echo "错误: Debian/Ubuntu 源码安装需要 systemd，脚本不会自动回退 apt 安装以避免卡住。"
        return 1
    fi

    CHECK_SOURCE_INSTALL_PREREQS || return 1
    INSTALL_FAIL2BAN_FROM_SOURCE
}

INSTALL_PACKAGE(){
    local package_name=$1

    case "${release}" in
        centos)
            if command -v dnf &> /dev/null; then
                RUN_DNF -y install "$package_name"
            else
                RUN_YUM -y install "$package_name"
            fi
            ;;
        debian|ubuntu)
            RUN_APT_GET -y install "$package_name"
            ;;
        *)
            return 1
            ;;
    esac
}

ENSURE_AUTH_LOG_FILE(){
    local log_file=$1

    [[ -f "$log_file" ]] && return 0

    case "${release}" in
        centos)
            if IS_EL9_OR_NEWER; then
                return 1
            fi

            echo "正在启用 rsyslog 日志文件后端，避免 fail2ban 扫描完整 journal..."
            if ! command -v rsyslogd &> /dev/null; then
                INSTALL_PACKAGE rsyslog || return 1
            fi

            SERVICE_CONTROL rsyslog enable >/dev/null 2>&1 || true
            SERVICE_CONTROL rsyslog restart >/dev/null 2>&1 \
                || SERVICE_CONTROL rsyslog start >/dev/null 2>&1 \
                || true

            touch "$log_file" 2>/dev/null || true
            chmod 600 "$log_file" 2>/dev/null || true
            [[ -f "$log_file" ]]
            ;;
        *)
            return 1
            ;;
    esac
}

CONFIGURE_FAIL2BAN_RESOURCE_LIMITS(){
    CHECK_SERVICE_MANAGER

    if [[ "$SERVICE_MANAGER" != "systemd" ]]; then
        return 0
    fi

    mkdir -p /etc/systemd/system/fail2ban.service.d
    cat > /etc/systemd/system/fail2ban.service.d/resource-limits.conf <<EOF
[Service]
Nice=10
CPUAccounting=true
CPUQuota=10%
EOF
    systemctl daemon-reload
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
    ASSERT_ROOT
    local fail2ban_already_installed=false

    CHECK_OS

    if [[ "$release" == "unknown" ]]; then
        echo "不支持的操作系统。请使用CentOS/RHEL/Rocky/AlmaLinux/Debian/Ubuntu系统."
        exit 1
    fi

    if command -v fail2ban-client &> /dev/null && \
        command -v fail2ban-server &> /dev/null && \
        FAIL2BAN_SERVICE_EXISTS; then
        fail2ban_already_installed=true
        echo "检测到 fail2ban 已安装，先停止旧服务以释放 CPU。"
        SERVICE_CONTROL fail2ban stop >/dev/null 2>&1 || true
    fi

    GET_SETTING_FAIL2BAN_INFO

    if [[ "$fail2ban_already_installed" == true ]]; then
        echo "检测到 fail2ban 已安装，将更新配置。"
        CONFIGURE_FAIL2BAN_RESOURCE_LIMITS
        return 0
    fi

    case "${release}" in
        centos)
            # 检测包管理器
            if command -v dnf &> /dev/null; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi

            echo "正在安装fail2ban (使用 $PKG_MANAGER)..."
            if ! IS_EL9_OR_NEWER; then
                ENABLE_EL_REPOS "$PKG_MANAGER" || {
                    echo "错误: EPEL 仓库启用失败，无法安装 fail2ban。"
                    exit 1
                }
            else
                DISABLE_INCOMPATIBLE_EL_REPOS
            fi
            INSTALL_FAIL2BAN_PACKAGE_EL "$PKG_MANAGER" || {
                echo "错误: fail2ban 安装失败。"
                exit 1
            }
            ;;
        debian|ubuntu)
            echo "正在安装fail2ban (源码包方式，跳过 apt 包触发器)..."
            INSTALL_FAIL2BAN_PACKAGE_DEB || {
                echo "错误: fail2ban 安装失败。"
                exit 1
            }
            ;;
        *)
            echo "请使用CentOS/RHEL/Rocky/AlmaLinux/Debian/Ubuntu系统."
            exit 1
            ;;
    esac

    ASSERT_FAIL2BAN_INSTALLED || exit 1
    CONFIGURE_FAIL2BAN_RESOURCE_LIMITS
}

REMOVE_FAIL2BAN(){
    ASSERT_ROOT
    local installed_from_source=false

    if [[ ! -e /etc/fail2ban/jail.local ]] && \
        [[ ! -e /etc/fail2ban/install-method ]] && \
        ! command -v fail2ban-client &> /dev/null; then
        echo "fail2ban尚未安装."
        exit 0
    fi

    CHECK_OS
    SERVICE_CONTROL fail2ban stop

    if [[ -f /etc/fail2ban/install-method ]] && grep -q '^source$' /etc/fail2ban/install-method; then
        installed_from_source=true
        if [[ -f /etc/fail2ban/source-install-files.txt ]]; then
            while IFS= read -r installed_file; do
                [[ -n "$installed_file" && -e "$installed_file" ]] && rm -f "$installed_file"
            done < /etc/fail2ban/source-install-files.txt
        fi
        rm -rf /usr/local/lib/fail2ban
    else
        case "${release}" in
            centos)
                if command -v dnf &> /dev/null; then
                    RUN_DNF -y remove fail2ban
                else
                    RUN_YUM -y remove fail2ban
                fi
                ;;
            debian|ubuntu)
                RUN_APT_GET -y remove --purge fail2ban
                RUN_APT_GET -y autoremove
                ;;
        esac
    fi

    if [[ "$installed_from_source" == true ]]; then
        rm -f /etc/systemd/system/fail2ban.service
    fi
    rm -rf /etc/systemd/system/fail2ban.service.d
    systemctl daemon-reload 2>/dev/null || true
    rm -rf /etc/fail2ban/jail.local /etc/fail2ban/install-method /etc/fail2ban/source-install-files.txt
    echo "fail2ban已卸载."
}

SETTING_FAIL2BAN(){
    CHECK_OS
    ASSERT_FAIL2BAN_INSTALLED || exit 1
    SERVICE_CONTROL fail2ban stop >/dev/null 2>&1 || true
    GET_SSH_SERVICE_NAME
    DETECT_FIREWALL

    # 根据发行版确定默认日志文件
    case "${release}" in
        centos)
            DEFAULT_LOG_FILE="/var/log/secure"
            ENSURE_AUTH_LOG_FILE "$DEFAULT_LOG_FILE" || true
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
        ENSURE_SYSTEMD_BACKEND_SUPPORT || {
            echo "错误: systemd journal 后端依赖安装失败。"
            exit 1
        }

        # 使用 systemd journal
        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1
dbpurgeage = 1d

[sshd]
enabled = true
filter = sshd
backend = systemd
journalmatch = _SYSTEMD_UNIT=${SSH_SERVICE}.service
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
dbpurgeage = 1d

[sshd]
enabled = true
filter = sshd
backend = polling
logpath = ${DEFAULT_LOG_FILE}
maxretry = ${BLOCKING_THRESHOLD}
findtime = 3600
bantime = ${BLOCKING_TIME_S}
action = ${FAIL2BAN_ACTION}
EOF
    fi

    CONFIGURE_FAIL2BAN_RESOURCE_LIMITS
    SERVICE_CONTROL fail2ban stop >/dev/null 2>&1 || true
    DISABLE_FAIL2BAN_AUTO_START

    echo "fail2ban配置完成，服务未启动，开机自启未启用。"
    echo "如需启动，请执行: bash fail2ban.sh start"
    echo "使用的防火墙: $FIREWALL_TYPE"
    echo "使用的日志后端: $LOG_BACKEND"
}

START_FAIL2BAN(){
    ASSERT_ROOT
    CHECK_OS
    ASSERT_FAIL2BAN_INSTALLED || exit 1
    CONFIGURE_FAIL2BAN_RESOURCE_LIMITS

    SERVICE_CONTROL fail2ban start || {
        echo "错误: fail2ban 启动失败，请执行 journalctl -u fail2ban -n 80 --no-pager 查看原因。"
        exit 1
    }

    echo "fail2ban已启动。"
}

RESTART_FAIL2BAN(){
    ASSERT_ROOT
    CHECK_OS
    ASSERT_FAIL2BAN_INSTALLED || exit 1
    CONFIGURE_FAIL2BAN_RESOURCE_LIMITS

    SERVICE_CONTROL fail2ban restart || {
        echo "错误: fail2ban 重启失败，请执行 journalctl -u fail2ban -n 80 --no-pager 查看原因。"
        exit 1
    }

    echo "fail2ban已重启。"
}

ENABLE_FAIL2BAN(){
    ASSERT_ROOT
    CHECK_OS
    ASSERT_FAIL2BAN_INSTALLED || exit 1
    CONFIGURE_FAIL2BAN_RESOURCE_LIMITS

    SERVICE_CONTROL fail2ban enable || {
        echo "错误: fail2ban 开机启动配置失败。"
        exit 1
    }

    echo "fail2ban 开机启动已启用。"
}

STOP_FAIL2BAN(){
    ASSERT_ROOT
    SERVICE_CONTROL fail2ban stop >/dev/null 2>&1 || true
    pkill -f fail2ban-server >/dev/null 2>&1 || true
    pkill -9 -f fail2ban-server >/dev/null 2>&1 || true
    echo "fail2ban 已停止。"
}

EMERGENCY_STOP_FAIL2BAN(){
    ASSERT_ROOT
    STOP_FAIL2BAN >/dev/null 2>&1 || true
    pkill -9 -f dnf >/dev/null 2>&1 || true
    pkill -9 -f yum >/dev/null 2>&1 || true
    pkill -9 -f rpm >/dev/null 2>&1 || true
    pkill -9 -x apt >/dev/null 2>&1 || true
    pkill -9 -x apt-get >/dev/null 2>&1 || true
    pkill -9 -x dpkg >/dev/null 2>&1 || true
    pkill -9 -x dpkg-deb >/dev/null 2>&1 || true
    pkill -9 -x mandb >/dev/null 2>&1 || true
    echo "fail2ban 和包管理器进程已停止。CPU 恢复后可重新执行: bash fail2ban.sh install"
}

DIAGNOSE_LOAD(){
    echo "【CPU Top】"
    ps -eo pid,ppid,stat,pcpu,pmem,comm,args --sort=-pcpu | sed -n '1,12p'
    echo
    echo "【fail2ban service】"
    SERVICE_CONTROL fail2ban status 2>/dev/null || echo "fail2ban service 不可用或未安装"
    echo
    echo "【包管理器进程】"
    local found_pkg_process=false
    pgrep -a -f dnf && found_pkg_process=true
    pgrep -a -f yum && found_pkg_process=true
    pgrep -a -f rpm && found_pkg_process=true
    pgrep -a -x apt && found_pkg_process=true
    pgrep -a -x apt-get && found_pkg_process=true
    pgrep -a -x dpkg && found_pkg_process=true
    pgrep -a -x dpkg-deb && found_pkg_process=true
    pgrep -a -x mandb && found_pkg_process=true
    [[ "$found_pkg_process" == true ]] || echo "未发现 dnf/yum/rpm/apt/dpkg/man-db 进程"
}

VIEW_RUN_LOG(){
    CHECK_OS
    GET_SSH_SERVICE_NAME

    case "${release}" in
        centos)
            if [[ -f /var/log/secure ]]; then
                tail -f /var/log/secure
            else
                echo "使用journalctl查看日志..."
                journalctl -u $SSH_SERVICE -f
            fi
            ;;
        debian|ubuntu)
            if [[ -f /var/log/auth.log ]]; then
                tail -f /var/log/auth.log
            else
                echo "使用journalctl查看日志..."
                journalctl -u $SSH_SERVICE -f
            fi
            ;;
    esac
}

GET_BANNED_IPS(){
    local banned_ips=""

    if banned_ips="$(fail2ban-client get "${JAIL_NAME}" banip 2>/dev/null)"; then
        echo "${banned_ips}" | tr ',' ' '
        return 0
    fi

    fail2ban-client status "${JAIL_NAME}" 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p' | tr ',' ' '
}

IS_IP_BANNED(){
    local target_ip="$1"
    local banned_ips=""

    banned_ips="$(GET_BANNED_IPS)"
    banned_ips=" ${banned_ips} "

    [[ "${banned_ips}" == *" ${target_ip} "* ]]
}

case "${1}" in
    install)
        INSTALL_FAIL2BAN
        SETTING_FAIL2BAN
        ;;
    emergency-stop|safe-stop)
        EMERGENCY_STOP_FAIL2BAN
        ;;
    diagnose|diag)
        DIAGNOSE_LOAD
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
            fail2ban-client status "${JAIL_NAME}"
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

        if ! [[ "${UNLOCK_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
            echo "错误: 无效的 IP 地址格式: ${UNLOCK_IP}"
            exit 1
        fi

        if ! fail2ban-client status "${JAIL_NAME}" >/dev/null 2>&1; then
            echo "错误: fail2ban jail ${JAIL_NAME} 不存在或未运行."
            exit 1
        fi

        if ! IS_IP_BANNED "${UNLOCK_IP}"; then
            echo "IP ${UNLOCK_IP} 当前不在 fail2ban 封禁列表中."
            echo "如果它仍然无法连接，请检查云安全组、系统防火墙手工规则或其他网络限制."
            exit 0
        fi

        if ! fail2ban-client set "${JAIL_NAME}" unbanip "${UNLOCK_IP}"; then
            echo "错误: fail2ban 执行解封失败."
            exit 1
        fi

        if IS_IP_BANNED "${UNLOCK_IP}"; then
            echo "错误: IP ${UNLOCK_IP} 仍然出现在 fail2ban 封禁列表中."
            exit 1
        fi

        echo "IP ${UNLOCK_IP} 已从 fail2ban 封禁列表移除."
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
        START_FAIL2BAN
        ;;
    stop)
        STOP_FAIL2BAN
        ;;
    restart)
        RESTART_FAIL2BAN
        ;;
    enable)
        ENABLE_FAIL2BAN
        ;;
    *)
        echo "bash fail2ban.sh {install|uninstall|runlog|more}"
        echo "bash fail2ban.sh {emergency-stop|safe-stop|diagnose}"
        echo "bash fail2ban.sh {start|stop|restart|enable|status}"
        echo "bash fail2ban.sh {blocklist|unlock}"
        ;;
esac

#END
