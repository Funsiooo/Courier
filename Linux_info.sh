#!/bin/bash



# 定义 banner 样式
banner=$(cat << EOF
.____    .__                          .__        _____       
|    |   |__| ____  __ _____  ___     |__| _____/ ____\____  
|    |   |  |/    \|  |  \  \/  /     |  |/    \   __\/  _ \ 
|    |___|  |   |  \  |  />    <      |  |   |  \  | (  <_> )
|_______ \__|___|  /____//__/\_ \_____|__|___|  /__|  \____/ 
        \/       \/            \/_____/       \/             
                                                  
EOF
)


# 输出 banner 和标题
echo -e "\n$banner\n"
echo -e "$(date +"%Y-%m-%d %H:%M:%S")"



# 创建 result 目录
if [ ! -d "result/logs" ]; then
    mkdir -p result/logs
fi


# 确保以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo "请以 root 权限运行该脚本"
    exit 1
fi

# 收集 IP 地址信息
echo "[-] 正在收集IP信息" 
ip addr >> result/IP信息.txt
echo "[*] IP信息已收集完毕"

echo "[-] 正在收集历史命令信息"
history >> result/历史命令.txt
echo "[*] 历史命令信息已收集完毕"

# 查看当前登录用户
echo "[-] 正在收集当前登录用户" 
w >> result/当前登录用户.txt
echo "[*] 当前登录用户信息已收集完毕" 

echo "[-] 正在收集最近登录用户信息" 
# 查看最近登录的用户
last >> result/最近登录用户.txt
echo "[*] 最近登录用户信息已收集完毕"

# 查看 /etc/passwd
echo "[-] 正在收集系统用户信息" 
cat /etc/passwd >> result/系统用户信息.txt
echo "[*] 系统用户信息已收集完毕" 

# 查看具有 root 权限的用户
echo "[-] 当前收集具有root权限用户信息" 
awk -F':' '$3 == 0 {print $1}' /etc/passwd >> result/root权限用户.txt
echo "[*] 当前具有root权限用户信息已收集完毕" 

# 检测空口令账户
echo "[-] 当前收集空口令账户信息" 
awk -F':' '($2 == "") {print $1}' /etc/shadow >> result/空口令账户账号.txt
echo "[-] 空口令账户信息已收集完毕" 

# 新增用户检查
echo "[-] 正在收集新增用户信息" 
cut -d':' -f1 /etc/passwd | sort | uniq -c | sort -nr >> result/新增用户.txt
echo "[*] 新增用户信息已收集完毕" 

# 新增用户组检查
echo "[-] 正在收集新增用户组信息" 
cut -d':' -f1 /etc/group | sort | uniq -c | sort -nr >> result/新增用户组.txt
echo "[*] 新增用户组信息已收集完毕" 

# 最近20行的身份验证日志
echo "[-] 正在收集最近20行的身份验证日志" 
tail -n 20 /var/log/auth.log >> result/最近20行的身份验证日志.txt
echo "[*] 最近20行的身份验证日志信息已收集完毕" 


# 查看使用 shell 的用户
echo "[-] 正在收集使用shell用户信息" 
cat /etc/passwd | grep -v nologin | grep -v false | awk -F':' '{print $1,$7}' >> result/正在收集使用shell用户.txt
echo "[*] 正在收集使用shell用户信息已收集完毕" 

# 查询系统中所有账户
echo "[-] 正在收集系统中所有用户" 
cat /etc/passwd | awk -F: '{print $1}' >> result/系统中所有用户.txt
echo "[*] 系统中所有用户信息已收集完毕" 

# 检测 sudoers 文件中的用户权限
echo "[-] 正在收集具有 NOPASSWD 权限的用户信息" 
grep NOPASSWD /etc/sudoers >> result/具有NOPASSWD权限的用户.txt
echo "[-] 具有 NOPASSWD 权限的用户信息已收集完毕"

# 检查各账户下是否存在 ssh 登录公钥
echo "[-] 正在收集SSH 公钥检查信息"
for user in $(cut -d':' -f1 /etc/passwd); do
    if [ -f /home/$user/.ssh/authorized_keys ]; then
        echo "用户 $user 存在 SSH 公钥" >> result/SSH公钥检查信息.txt
    fi
done
echo "[*] SSH 公钥检查信息已收集完毕"

# 账户密码文件权限检测
echo "[-] 正在收集账户密码文件权限信息"
ls -l /etc/shadow /etc/passwd >> result/账户密码文件权限信息.txt
echo "[-] 账户密码文件权限信息已收集完毕"

# 查看全部进程
echo "[-] 正在收集系统全部进程信息"
ps -aux >> result/系统全部进程信息.txt
echo "[*] 系统全部进程信息已收集完毕"

# 查看当前运行的守护进程
echo "[-] 正在收集系统正在运行的守护进程信息"
ps -ef >> result/当前运行的守护进程信息.txt
echo "[*] 系统正在运行的守护进程信息已收集完毕"

# 查询正在监听的端口
echo "[-] 正在收集正在监听的端口信息"
netstat -antp >> result/正在监听的端口信息信息.txt
echo "[-] 正在监听的端口信息已收集完毕"

# 查询外联情况
echo "[-] 正在收集外联信息"
netstat -antp | grep ESTABLISHED >> result/外联情况信息.txt
echo "[*] 外联信息已收集完毕"

# 检查 CPU 和内存使用率最高的进程
echo "[-] 正在收集CPU 和内存使用率Top 10的进程信息"
ps aux --sort=-%cpu,%mem | head -n 10 >> result/CPU和内存使用率最高的进程.txt
echo "[*] CPU 和内存使用率Top 10的进程信息已收集完毕"

# 用户自定义启动项排查
echo "[-] 正在收集用户自定义启动项信息"
for user in $(cut -d':' -f1 /etc/passwd); do
    if [ -d /home/$user/.config/autostart ]; then
        echo "用户 $user 存在自定义启动项" >> result/用户自定义启动项信息.txt
    fi
done
echo "[*] 用户自定义启动项信息已收集完毕"

# 系统自启动项排查
echo "[-] 正在收集系统自启动信息"
systemctl list-unit-files --type=service | grep enabled >> result/系统自启动项信息.txt
echo "[*] 系统自启动信息已收集完毕"

# 系统定时任务分析
echo "[-] 正在收集系统定时任务信息"
crontab -l >> result/系统定时任务信息.txt
cat /etc/crontab >> result/系统级别的定时任务配置文件信息.txt
echo "[*] 系统定时任务信息已收集完毕"

# 用户定时任务分析
echo "[-] 正在收集系统用户定时任务信息"
for user in $(cut -d':' -f1 /etc/passwd); do
    crontab -u $user -l >> result/用户定时任务信息.txt
done
echo "[*] 系统用户定时任务信息已收集完毕"

# 日志审核状态
echo "[-] 正在收集系统日志审核状态信息"
systemctl status rsyslog >> result/日志审核状态信息.txt
echo "[*] 系统日志审核状态信息已收集完毕"

# 打包日志
echo "[-] 正在收集系统日志至logs目录"
tar -czf ./result/logs/logs.tar.gz /var/log/
echo "[*] 系统日志已Copy至logs目录"

# 日志分析
echo "[-] 正在收集最近登录失败用户信息" 
# 查看最近登录失败的用户
lastb >> result/最近登录失败用户信息.txt
echo "[*] 最近登录失败用户信息已收集完毕"

# 查看服务器是否被暴力破解
echo "正在收集服务器是否被暴力破解信息:" >> result/linux.txt
cat /var/log/auth.log | grep "Failed password" >> result/服务器是否被暴力破解.txt
cat /var/log/secure | grep "Failed password" >> result/服务器是否被暴力破解.txt
echo "[*] 服务器是否被暴力破解信息已收集完毕"


# 检查正在运行的服务
echo "[-] 正在收集服务器正在运行的服务信息"
systemctl list-units --type=service --state=running >> result/正在运行的服务信息.txt
echo "[-] 服务器正在运行的服务信息已收集完毕"


# Alias 后门检测
echo "[-] 正在收集服务器是否存在 Alias 后门信息"
cat ~/.bashrc | grep alias >> result/Alias后门检测信息.txt
echo "[*] 是否存在 Alias 后门信息已收集完毕"


# SSH 后门检测
echo "[-] 正在收集服务器是否存在 SSH 后门信息"
lsof -i:22 >> result/SSH后门检测信息.txt
echo "[*] 是否存在 SSH 后门信息已收集完毕"


# SSH Wrapper 后门检测
echo "[-] 正在收集服务器是否存在 SSH Wrapper 后门信息"
find / -name "*ssh*" -type f -exec ls -l {} \; >> result/SSHWrapper后门检测信息.txt
echo "[*] 是否存在 SSH Wrapper 后门信息已收集完毕"


# 检查 SSH 授权密钥文件是否包含可疑命令
echo "[-] 正在收集服务器SSH 授权密钥文件信息"
for user in $(cut -d':' -f1 /etc/passwd); do
    if [ -f /home/$user/.ssh/authorized_keys ]; then
        echo "用户 $user 的 SSH 授权密钥文件:" >> result/SSH授权密钥文件检查信息.txt
        cat /home/$user/.ssh/authorized_keys >> result/SSH授权密钥文件检查信息.txt
    fi
done
echo "[*] 服务器SSH 授权密钥文件信息已收集完毕"

# 检查特定目录中是否存在可疑文件
echo "[-] 正在收集服务器特定目录是否存在可疑文件信息"
find /tmp /var/tmp /dev/shm -type f -exec ls -l {} \; >> result/特定目录是否存在可疑文件信息.txt
echo "[*] 服务器特定目录是否存在可疑文件信息已收集完毕"

# 检查系统日志中是否包含可疑内容
echo "[-] 正在收集系统/var/log/*目录下日志是否存在可疑信息"
grep -E 'suspicious|malicious|unauthorized' /var/log/* >> result/系统日志中是否包含可疑内容信息.txt
echo "[*] 系统/var/log/*目录下日志是否存在可疑信息已收集完毕"

# 防火墙配置检测
echo "[-] 正在收集防火墙配置信息"
iptables -L >> result/防火墙配置信息.txt
echo "[*] 防火墙配置信息已收集完毕"


echo "当前时间是: $(date +"%Y-%m-%d %H:%M:%S")"


#! var/log日志文件
# /var/log/wtmp      登录进入，退出，数据交换、关机和重启纪录，即last
# /var/log/lastlog   文件记录用户最后登录的信息，即lastlog
# /var/log/secure    记录登入系统存取数据的文件，如 pop3/ssh/telnet/ftp
# /var/log/cron      与定时任务相关的日志信息
# /var/log/message   系统启动后的信息和错误日志
# /var/log/message   包括整体系统信息
# /var/log/auth.log  包含系统授权信息，包括用户登录和使用的权限机制等
# /var/log/userlog   记录所有等级用户信息的日志
# /var/log/cron      记录crontab命令是否被正确的执行
# /var/log/lastlog   记录登录的用户，可以使用命令lastlog查看
# /var/log/secure    记录大多数应用输入的账号与密码，登录成功与否
# var/log/faillog    记录登录系统不成功的账号信息
# /var/log/boot.log  记录自检过程
# /var/log/maillog   发送到系统或从系统发出的电子邮件的活动
# /var/log/syslog    记录警告信息，系统出问题的信息
# /var/run/utmp      该日志文件记录有关当前登录的每个用户的信息
# /var/log/xferlog   该日志文件记录FTP会话，可以显示出用户向FTP服务器或从服务器拷贝了什么文件
# /var/log/apache2/access.log apache access log
# /var/log/xferlog(vsftpd.log)记录Linux FTP日志

#! lsof 常用命令
# 安装命令：Debian/Ubuntu: sudo apt-get install lsof、CentOS/RHEL: sudo yum install lsof
# lsof -p PID、ls -al /proc/9109/exe 定位可疑进程文件位置
# lsof -i 显示所有连接
# lsof -i 4 查看IPv4流量
# lsof -i 6 查看IPv6流量
# lsof -i TCP 查看TCP流量
# lsof -i UDP 查看UDP流量
# lsof -i :22 查看端口绑定的应用
# lsof -i@1.1.1.1 显示指定主机连接的信息
# lsof -i@1.1.1.1:3333 显示基于主机与端口连接的信息
# lsof -i -sTCP:LISTEN 显示正在监听的端
# lsof -i -sTCP:ESTABLISHED 显示已建立连接信息
# lsof -u root 显示指定用户打开文件信息
# lsof -u ^root 显示除指定用户外打开文件信息
# lsof -p 22222 显示指定PID打开文件信息
# lsof /var/log/messages 显示与指定目录交互的所有一切
# lsof /home/daniel/firewall_whitelist.txt 显示与指定文件交互的所有一切

#! ps 常用命令
# ps -ef 列出所有进程
# ps -aux 查看全部进程
# ps -aux | grep pid 查看关联进程
# ps -ef | grep pid号 定位可疑进程的程序是什么
# ps -ef | grep <process_name> 搜索进程名定位文件
# ps -eo pid,user,etime,command --sort=-etime 按进程启动时间排序
# ps -u username -f 列出特定用户的进程
# ps -ef | grep -i listen 列出正在监听网络端口的进程
# ps -ef | grep -i root 列出拥有 root 权限的进程
# ps -eo pid,etime,user,args --sort=-etime | head -n 10 列出运行时间超过一定时间的进程
# pstree -p 查看进程的父子关系
# ps -ef | awk '{print $2,$8}' | grep defunct 列出僵尸进程
# ps -ef | grep -v grep | grep -E '^root|^daemon' 查询特定用户守护进程命令




#! netstat 常用命令
# netstat -antp 列出所有网络连接
# netstat -pantu 查看端口开放和连接情况
# netstat -antp | grep ":80" 列出与特定端口建立连接的进程
# netstat -antp | grep LISTEN 列出正在监听的端口
# netstat -antp | awk '{print $7}' | cut -d'/' -f1 | sort | uniq -c | sort -nr 按进程列出网络连接
# netstat -antp | grep tcp 列出tcp协议的网络连接
# netstat -anup | grep udp 列出udp协议的网络连接
# netstat -antp | awk '{print $5}' | cut -d':' -f1 | sort | uniq -c | sort -nr 列出远程连接的 IP 地址
# netstat -antp | awk '{print $6}' | sort | uniq -c | sort -nr 列出网络流量统计


#! ls 命令
# ls -l 列出当前目录的所有文件和目录
# ls -lR 递归列出目录及其子目录下的所有文件和目录
# ls -la 列出隐藏文件
# ls -lt 按修改时间排序
# ls -alt 按时间倒序
# ls -lS 按文件大小排序
# ls -d */ 只列出目录
# ls -l *.txt 列出指定文件类型
# ls -ln /file_name 列出文件的属主和属组


#! 可疑文件排查
# 统计爆破主机root账号的失败次数及ip
# grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
#
# 定位哪些IP在爆破
# grep "Failed password" /var/log/secure|grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"|uniq -c
#
# 查看成功登录的日期、用户名、IP
# grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'
#
# 爆破用户名字典是什么？
# grep "Failed password" /var/log/secure|perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}'|uniq -c|sort -nr 
#
# 特权文件排查
# find / -perm 2000 2>/dev/null
#
# 排查临时目录
# find /tmp ! -type d -exec ls -lctr --full-time {} \+ 2>/dev/null
#
# 排查 HOME 目录
# find $HOME ! -type d -exec ls -lctr --full-time {} \+ 2>/dev/null
#
# 文件创建及修改时间查询
# stat 【文件名路径/文件名】
#
# 查看文件被哪个进程使用
# lsof 【文件路径/文件名】


#! 计划任务
# 查看计划任务
# crontab  -l

# 查看指定用户计划任务
# crontab -u 用户名 -l

# 查看计划任务
# cat /var/spool/cron/* centos
# cat /var/spool/cron/crontabs/* ubuntu的
# cat /etc/crontab
# cat /etc/cron.d/*
# cat /etc/cron.daily/* 
# cat /etc/cron.hourly/* 
# cat /etc/cron.monthly/*
# cat /etc/cron.weekly/
# cat /etc/anacrontab 异步定时
# cat /var/spool/anacron/*
# cat crontab  -l 查看定时任务
# cat crontab –e 编辑定时任务
# ls /var/spool/cron/ 查看每个用户自己的执行计划


#! 日志排查
# 终端输出指定日志指定时间的日志
# cat /var/log/syslog | grep "YYYY-MM-DD HH:MM:SS"

# 终端输出日志中指定 ip 的日志
# cat /var/log/syslog | grep "外部IP地址"

# 查看Linux服务器是否被暴力破解
# sudo cat /var/log/auth.log | grep "Failed password"


#! 常见日志存储目录
# 系统日志
# /var/log/messages
# /var/log/syslog
# /var/log/kern.log
# /var/log/auth.log
# 
# Web 服务器日志
# /var/log/apache2/access.log
# /var/log/apache2/error.log
# /var/log/nginx/access.log
# /var/log/nginx/error.log
# 
# 数据库日志
# /var/log/mysql/mysql.log
# /var/log/postgresql/postgresql-<version>-main.log
# 
# 应用服务器日志
# $CATALINA_HOME/logs/catalina.out
# $JBOSS_HOME/standalone/log/server.log
# $JETTY_HOME/logs/yyyy_mm_dd.stderrout.log
# /var/log/php-fpm/error.log
# /var/log/supervisor/supervisord.log
# 
# 中间件日志
# /opt/kafka/logs/server.log
# /opt/kafka/logs/controller.log
# /opt/kafka/logs/state-change.log
# /var/log/rabbitmq/rabbit@hostname.log
# /var/log/rabbitmq/rabbit@hostname-web.log
# /var/log/redis/redis.log
# 
# FTP 服务器日志
# /var/log/vsftpd.log
# /var/log/secure
# /var/log/proftpd/access.log
# /var/log/proftpd/error.log
# 
# 容器和虚拟化日志
# /var/lib/docker/containers/<container-id>/<container-id>-json.log
# /var/log/kube-apiserver.log
# /var/log/kube-controller-manager.log
# /var/log/kube-scheduler.log
# 
# 网络服务日志
# /var/log/dhcp.log
# /var/log/named.log
# /var/log/squid/access.log
# /var/log/squid/cache.log
# /var/log/maillog
#
# 
# 安全服务日志
# /var/log/firewalld.log
# /var/log/audit/audit.log
# /var/log/secure、/var/log/auth.log
#  # /var/log/btmp


# 文件内容中的恶意函数
# PHP：eval(、system(、assert(
# JSP：getRunTime(、 FileOutputStream(
# ASP：eval(、execute(、 ExecuteGlobal（


#! find 常用命令
# 查找名为 "sensitive.txt" 的文件
# find / -name "sensitive.txt" -type f
#
# 查找名为 "logs" 的目录
# find / -name "logs" -type d
#
# 查找最近 1 小时内修改的文件
# find / -mmin -60
#
# 查找最近 1 天内修改的文件
# find / -mtime -1
#
# 在所有文件中查找含有 "password" 字符串的文件
# find / -type f -exec grep -l "password" {} \;


#! 其它
# 保存历史命令
# cat .bash_history >>history.txt

# 检查系统文件的权限变更
# find / -mtime -7 -type f -exec ls -l {} \; >> result/linux.txt

# 检查 24 小时内有改变的文件
# find / -mtime -1 -type f -exec ls -l {} \; >> result/linux.txt
