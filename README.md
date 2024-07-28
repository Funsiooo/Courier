## 📖 简介

Courier 信使，自用应急响应信息收集脚本，便于快速进行信息收集、定位攻击信息。



## 🖨️ 支持收集
### Windows 应急响应
| 信息收集                   | 具体命令                                                     |
| -------------------------- | ------------------------------------------------------------ |
| ✅ IP 信息                  | ipconfig /all                                                |
| ✅ 用户信息及 SID           | net user <br/>wmic useraccount get name,sid,Description      |
| ✅ 网络连接                 | netstat -ano                                                 |
| ✅ ARP 信息                 | arp -a                                                       |
| ✅ HOST 信息                | type %SystemRoot%\System32\drivers\etc\hosts                 |
| ✅ 系统信息                 | for /f "delims=" %%a in ('wmic os get Caption^,CSName^,OSArchitecture^,Version^,BuildNumber /value') do (<br/>    set "%%a"<br/>    echo OS: %Caption%, %OSArchitecture%, Version %Version% Build %BuildNumber% >> result\system_information.txt<br/>) |
| ✅ 用户最近访问记录         | dir %APPDATA%\Microsoft\Windows\Recent                       |
| ✅ 计划任务                 | schtasks /query /fo LIST /v                                  |
| ✅ Windows Temp 文件        | dir %SystemRoot%\Temp                                        |
| ✅ 预读取 Prefetch 文件     | dir %SystemRoot%\Prefetch                                    |
| ✅ 进程列表                 | tasklist /V                                                  |
| ✅ 路由表                   | route print                                                  |
| ✅ 系统启动项               | reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run<br/>reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| ✅ 注册表信息               | reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\run"<br/>reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"<br/>reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Runonce" |
| ✅ 系统日志                 | copy "C:\Windows\System32\winevt\Logs\System.evtx" result\logs\System.evtx<br/>copy "C:\Windows\System32\winevt\Logs\Security.evtx" result\logs\Security.evtx<br/>copy "C:\Windows\System32\winevt\Logs\Application.evtx" result\logs\Application.evtx<br/>copy "C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx" "result\logs\Windows PowerShell.evtx" |
| ✅ 远程桌面记录             | wevtutil qe "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /c:10 /rd:true /f:text |
| ✅ DNS 缓存记录             | ipconfig /displaydns >> result\system_information.txt        |
| ✅ 系统补丁                 | wmic qfe list full<br/>systeminfo                            |
| ✅ 计算机之间会话信息       | at<br/>schtasks.exe                                          |
| ✅ 搜索指定时间修改过的文件 | forfiles /m *.exe /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.dll /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.vbs /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.bat /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.ps1 /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.sys /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.com /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.bin /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.lnk /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.ocx /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.drv /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.jsp /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.jspx /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.asp /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.aspx /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null<br/>forfiles /m *.php /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null |
| ✅ 近三天内修改的文件       | forfiles /p %userprofile% /s /m * /d -3 /c "cmd /c echo @path" |
| ✅ 系统服务                 | net start                                                    |
| ✅ 已装软件                 | wmic product get name,version,vendor                         |
| ✅ 硬件信息                 | wmic nic get name,macaddress,speed<br/>wmic memcache get speed,status,purpose<br/>wmic memphysical get maxmemorymodulesize, speed |
| ✅ 防火墙                   | netsh advfirewall show allprofiles                           |
| ✅ USB 使用信息             | wmic usb get DeviceId,Description,Name                       |
| ✅ 共享资源                 | net share                                                    |

### Linux 应急响应
| 信息收集                                | 具体命令                                                     |
| --------------------------------------- | ------------------------------------------------------------ |
| ✅ IP 地址                               | ip addr                                                      |
| ✅ 历史命令                              | history                                                      |
| ✅ 当前登录用户                          | w                                                            |
| ✅ 最近登录的用户                        | last                                                         |
| ✅ 查看 /etc/passwd                      | cat /etc/passwd                                              |
| ✅ 查看具有 root 权限的用户              | awk -F':' '$3 == 0 {print $1}' /etc/passwd                   |
| ✅ 检测空口令账户                        | awk -F':' '($2 == "") {print $1}' /etc/shadow                |
| ✅ 新增用户检查                          | cut -d':' -f1 /etc/passwd                                    |
| ✅ 新增用户组检查                        | cut -d':' -f1 /etc/group                                     |
| ✅ 最近20行的身份验证日志                | tail -n 20 /var/log/auth.log                                 |
| ✅ 查看使用 shell 的用户                 | cat /etc/passwd                                              |
| ✅ 查询系统中所有账户                    | cat /etc/passwd                                              |
| ✅ 检测 sudoers 文件中的用户权限         | grep NOPASSWD /etc/sudoers                                   |
| ✅ 检查各账户下是否存在 ssh 登录公钥     | for user in $(cut -d':' -f1 /etc/passwd); do<br/>    if [ -f /home/$user/.ssh/authorized_keys ]; then<br/>        echo "用户 $user 存在 SSH 公钥" >> result/SSH公钥检查信息.txt<br/>    fi<br/>done |
| ✅ 账户密码文件权限检测                  | ls -l /etc/shadow /etc/passwd                                |
| ✅ 查看全部进程                          | ps -aux                                                      |
| ✅ 查看当前运行的守护进程                | ps -ef                                                       |
| ✅ 查询正在监听的端口                    | netstat -antp                                                |
| ✅  查询外联情况                         | netstat -antp \| grep ESTABLISHED                            |
| ✅ 检查 CPU 和内存使用率最高的进程       | ps aux --sort=-%cpu,%mem                                     |
| ✅ 用户自定义启动项排查                  | for user in $(cut -d':' -f1 /etc/passwd); do<br/>    if [ -d /home/$user/.config/autostart ]; then<br/>        echo "用户 $user 存在自定义启动项" >> result/用户自定义启动项信息.txt<br/>    fi<br/>done |
| ✅ 系统自启动项排查                      | systemctl list-unit-files --type=service                     |
| ✅ 系统定时任务分析                      | crontab -l <br/>cat /etc/crontab                             |
| ✅ 用户定时任务分析                      | for user in $(cut -d':' -f1 /etc/passwd); do<br/>    crontab -u $user -l >> result/用户定时任务信息.txt<br/>done |
| ✅ 日志审核状态                          | systemctl status rsyslog                                     |
| ✅ 打包日志                              | tar -czf ./result/logs/logs.tar.gz /var/log/                 |
| ✅ 日志分析                              | lastb                                                        |
| ✅ 查看服务器是否被暴力破解              | cat /var/log/auth.log \| grep "Failed password"<br/>cat /var/log/secure \| grep "Failed password" |
| ✅ 检查正在运行的服务                    | systemctl list-units --type=service --state=running          |
| ✅ Alias 后门检测                        | cat ~/.bashrc                                                |
| ✅ SSH 后门检测                          | lsof -i:22                                                   |
| ✅ SSH Wrapper 后门检测                  | find / -name "*ssh*" -type f -exec ls -l {} \;               |
| ✅ 检查 SSH 授权密钥文件是否包含可疑命令 | for user in $(cut -d':' -f1 /etc/passwd); do<br/>    if [ -f /home/$user/.ssh/authorized_keys ]; then<br/>        echo "用户 $user 的 SSH 授权密钥文件:" >> result/SSH授权密钥文件检查信息.txt<br/>        cat /home/$user/.ssh/authorized_keys >> result/SSH授权密钥文件检查信息.txt<br/>    fi<br/>done |
| ✅ 检查特定目录中是否存在可疑文件        | find /tmp /var/tmp /dev/shm -type f -exec ls -l {} \;        |
| ✅ 检查系统日志中是否包含可疑内容        | grep -E 'suspicious\|malicious\|unauthorized' /var/log/*     |
| ✅ 防火墙配置检测                        | iptables -L                                                  |


## 🔨 使用
### Windows
⚠ 注意：.bat 中 `“搜索指定时间修改过的文件”` 时间根据需求自行修改 `forfiles /m *.exe /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null` 默认搜索 2024/7/23 后文件


1、管理员打开 CMD 执行，Win_info.bat，结果保存在当前目录的 /result 中

![image-1](https://github.com/Funsiooo/Courier/blob/main/images/1.png)

![image-2.1](https://github.com/Funsiooo/Courier/blob/main/images/2.1.png)

### Linux
root 用户给与权限： chmod +x Linux_info.sh，然后执行即可，结果保存在当前目录的 /result 中

![image-3](https://github.com/Funsiooo/Courier/blob/main/images/3.png)

![image-4](https://github.com/Funsiooo/Courier/blob/main/images/4.png)



## 📂辅助信息

打开 .bat、.sh 文件，脚本后面注释可查看相关辅助信息，便于开展响应工作，包括常见日志路径、工具命令等，可自行添加其它记录，方便信息查找。

![image-2](https://github.com/Funsiooo/Courier/blob/main/images/2.png)

![image-5](https://github.com/Funsiooo/Courier/blob/main/images/5.png)


## 🛎️ FQA

```
1、自用脚本，bug 慢修
2、若有其它思路需完善的可提issue
```

