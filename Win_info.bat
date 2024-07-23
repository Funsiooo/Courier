@echo off
chcp 65001 > nul

rem 创建 log 文件夹
mkdir result\logs

rem 输出当前日期和时间
echo %date% %time% >> result\info.txt 2>nul


echo.
rem 输出banner
echo #######################################################################
echo #                                                                     #
echo #                                                                     #
echo #               WINDOWS SYSTEM INFORMATION COLLECTION                 #
echo #                                                                     #
echo #                                                                     #
echo #######################################################################

echo.
echo [-] 正在收集IP信息已收集完毕
echo ========== IP 信息 ========== >> result\info.txt 2>nul
ipconfig /all >> result\info.txt 2>nul
echo [*] IP信息已收集完毕


echo [-] 正在收集用户信息及SID
echo ========== 用户信息及 SID ========== >> result\info.txt 2>nul
net user >> result\info.txt 2>nul
wmic useraccount get name,sid,Description >> result\info.txt 2>nul
echo [*] 用户信息及 SID 已收集完毕


echo [-] 正在收集网络连接信息
echo ========== 网络连接 ========== >> result\info.txt 2>nul
netstat -ano >> result\info.txt 2>nul
echo [*] 网络连接信息已收集完毕


echo [-] 正在收集ARP信息
echo ========== ARP 信息 ========== >> result\info.txt 2>nul
arp -a >> result\info.txt 2>nul
echo [*] ARP信息已收集完毕


echo [-] 正在收集HOST文件信息
echo ========== HOST 信息 ========== >> result\info.txt 2>nul
type %SystemRoot%\System32\drivers\etc\hosts >> result\info.txt 2>nul
echo [*] HOST文件信息已收集完毕


echo [-] 正在收集系统信息
echo ========== 系统信息 ========== >> result\info.txt 2>nul
for /f "delims=" %%a in ('wmic os get Caption^,CSName^,OSArchitecture^,Version^,BuildNumber /value') do (
    set "%%a"
    echo OS: %Caption%, %OSArchitecture%, Version %Version% Build %BuildNumber% >> result\info.txt 2>nul
)
echo [*] 系统信息已收集完毕


echo [-] 正在收集用户最近访问记录
echo ========== 用户最近访问记录 ========== >> result\info.txt 2>nul
dir %APPDATA%\Microsoft\Windows\Recent >> result\info.txt 2>nul
echo [*] 用户最近访问记录收集完毕


echo [-] 正在收集计划任务信息
echo ========== 计划任务 ========== >> result\info.txt 2>nul
schtasks /query /fo LIST /v >> result\info.txt 2>nul
echo [*] 计划任务信息已收集完毕


echo [-] 正在收集 Windows Temp 文件信息
echo ========== Windows Temp 文件 ========== >> result\info.txt 2>nul
dir %SystemRoot%\Temp >> result\info.txt 2>nul
echo [*] Windows Temp 文件信息收集完毕


echo [-] 正在收集预读取 Prefetch 文件
echo ========== 预读取 Prefetch 文件 ========== >> result\info.txt 2>nul
dir %SystemRoot%\Prefetch >> result\info.txt 2>nul
echo [*] 预读取 Prefetch 文件信息收集完毕


echo [-] 正在收集进程列表
echo ========== 进程列表 ========== >> result\info.txt 2>nul
tasklist /V >> result\info.txt 2>nul
echo [*] 进程列表信息收集完毕


echo [-] 正在收集路由表
echo ========== 路由表 ========== >> result\info.txt 2>nul
route print >> result\info.txt 2>nul
echo [*] 路由表信息收集完毕


echo [-] 正在收集系统启动项信息
echo ========== 系统启动项 ========== >> result\info.txt 2>nul
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> result\info.txt 2>nul
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run >> result\info.txt 2>nul
echo [*] 系统启动项信息收集完毕


echo [-] 正在收集注册表信息
echo ========== 注册表信息 ========== >> result\info.txt 2>nul
echo 注冊表用户启动项: >> result\info.txt 2>nul
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\run"
echo 注冊表系统设置启动项: >> result\info.txt 2>nul
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
echo 注冊表系统启动项: >> result\info.txt 2>nul
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Runonce"
echo [*] 注册表信息收集完毕


echo [-] 正在保存系统日志至result\logs文件夹
echo ========== 系统日志 ========== >> result\logs
echo 系统日志: >> result\logs
copy "C:\Windows\System32\winevt\Logs\System.evtx" result\logs\System.evtx
echo 安全日志: >> result\logs
copy "C:\Windows\System32\winevt\Logs\Security.evtx" result\logs\Security.evtx
echo 应用程序日志: >> result\logs
copy "C:\Windows\System32\winevt\Logs\Application.evtx" result\logs\Application.evtx
echo Powershell 日志: >> result\logs
copy "C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx" "result\logs\Windows PowerShell.evtx"
echo [*] 系统日志文件已保存至result\logs文件夹


echo [-] 正在收集mstsc远程连接记录
echo ========== mstsc远程连接记录 ========== >> result\info.txt 2>nul
wevtutil qe "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /c:10 /rd:true /f:text >> result\info.txt 2>nul
echo [*] mstsc远程连接记录信息收集完毕


echo [-] 正在收集DNS缓存记录
echo ========== DNS 缓存记录 ========== >> result\info.txt 2>nul
ipconfig /displaydns >> result\info.txt 2>nul
echo [*] DSN缓存记录收集完毕


echo [-] 正在收集系统补丁情况
echo ========== 系统补丁 ========== >> result\info.txt 2>nul
echo 补丁情况一: >> result\info.txt 2>nul
wmic qfe list full >> result\info.txt 2>nul
echo 补丁情况二: >> result\info.txt 2>nul
systeminfo >> result\info.txt 2>nul
echo [*] 系统补丁情况收集完毕


echo [-] 正在收集计算机之间会话信息
echo ========== 计算机之间会话信息 ========== >> result\info.txt 2>nul
echo 旧系统命令: >> result\info.txt 2>nul
at >> result\info.txt 2>nul
echo 新系统命令: >> result\info.txt 2>nul
schtasks.exe >> result\info.txt 2>nul
echo [*] 计算机之间会话信息收集完毕


echo [-] 正在收集搜索指定时间修改过的文件
echo ========== 搜索指定时间修改过的文件 ========== >> result\info.txt 2>nul

rem 查找指定2024年7月22日以后新增的程序
forfiles /m *.exe /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.dll /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.vbs /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.bat /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.ps1 /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.sys /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.com /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.bin /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.lnk /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.ocx /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.drv /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.jsp /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.jspx /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.asp /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.aspx /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
forfiles /m *.php /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>>null
echo [*] 指定时间修改过的文件信息已收集完毕


echo [-] 正在收集近三天内修改的文件
echo ========== 近三天内修改的文件 ========== >> result\info.txt 2>nul
forfiles /p %userprofile% /s /m * /d -3 /c "cmd /c echo @path" >> result\info.txt 2>nul
echo [*] 近三天内修改的文件信息收集完毕


echo [-] 正在收集系统服务信息
echo ========== 系统服务 ========== >> result\info.txt 2>nul
net start >> result\info.txt 2>nul
echo [*] 系统服务信息收集完毕


echo [-] 正在收集已装软件信息
echo ========== 已装软件 ========== >> result\info.txt 2>nul
wmic product get name,version,vendor >> result\info.txt 2>nul
echo [*] 已装软件信息收集完毕


echo [-] 正在收集硬件信息
echo ========== 硬件信息 ========== >> result\info.txt 2>nul
echo 网卡: >> result\info.txt 2>nul
wmic nic get name,macaddress,speed >> result\info.txt 2>nul
echo 缓存: >> result\info.txt 2>nul
wmic memcache get speed,status,purpose >> result\info.txt 2>nul
echo 物理内存: >> result\info.txt 2>nul
wmic memphysical get maxmemorymodulesize, speed >> result\info.txt 2>nul
echo [*] 集硬件信息收集完毕


echo [-] 正在收集防火墙信息
echo ========== 防火墙 ========== >> result\info.txt 2>nul
netsh advfirewall show allprofiles >> result\info.txt 2>nul
echo [*] 防火墙信息收集完毕


echo [-] 正在收集USB使用情况信息
echo ========== USB 使用信息 ========== >> result\info.txt 2>nul
wmic usb get DeviceId,Description,Name >> result\info.txt 2>nul
echo [*] USB使用情况信息已收集完毕


echo [-] 正在收集系统共享资源信息
echo ========== 共享资源 ========== >> result\info.txt 2>nul
net share >> result\info.txt 2>nul
echo [-] 系统共享资源信息已收集完毕


@rem 系统日志路径信息
rem Windows 系统日志
:: 事件日志: %SystemRoot%\System32\winevt\Logs

rem Web 服务器日志
:: IIS 日志: %SystemDrive%\inetpub\logs\LogFiles
:: Nginx 日志: <Nginx安装目录>>\logs
:: Apache 日志: <Apache安装目录>>\logs

rem 应用服务器日志
:: Tomcat 日志: %CATALINA_HOME%\logs
:: WebLogic 日志: %DOMAIN_HOME%\servers\%SERVER_NAME%\logs
:: JBoss 日志: <JBoss安装目录>>\standalone\log

rem 数据库服务器日志
:: SQL Server 日志: %PROGRAMDATA%\Microsoft\Microsoft SQL Server\MSSQL\Log
:: MySQL 日志: %PROGRAMDATA%\MySQL\MySQL Server 8.0\data
:: Oracle 日志: <Oracle安装目录>>\diag\rdbms\<SID>>\<SID>>\trace

rem 应用程序日志
:: .NET 应用程序日志: %ALLUSERSPROFILE%\<应用程序名称>>\Logs
:: Java 应用程序日志: <应用程序安装目录>>\logs

rem 网络设备日志
:: 路由器日志: 通常通过Web管理界面或专有软件查看
:: 交换机日志: 通常通过Web管理界面或专有软件查看

rem 邮件服务器日志
:: Exchange Server 日志: %ExchangeInstallPath%\Logging
:: Postfix 日志: /var/log/mail.log
:: Sendmail 日志: /var/log/maillog

rem FTP 服务器日志
:: Windows 自带 FTP 服务日志: %SystemRoot%\System32\LogFiles\FTPSVC
:: FileZilla FTP 服务日志: %AppData%\FileZilla\logs

rem 远程桌面服务日志
:: 远程桌面服务日志: %SystemRoot%\System32\LogFiles\Terminal Services
:: 此日志记录了远程桌面连接的相关信息,包括连接、断开、错误等

rem 应用程序日志
:: Microsoft Office 日志: %APPDATA%\Microsoft\Office\Outlook\Logging
:: Adobe Creative Cloud 日志: %APPDATA%\Adobe\Logs

rem 虚拟化平台日志
:: Hyper-V 日志: %SystemRoot%\System32\LogFiles\Hyper-V
:: VMware 日志: C:\ProgramData\VMware\VMware Workstation\Logs

rem Windows 防火墙日志
:: 位置: %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
:: 此日志记录了 Windows 防火墙的活动信息,包括允许/拒绝的连接等。

rem PowerShell 日志
:: 位置: %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PowerShell_transcript.<computername>>-<username>>-<yyyymmdd>>-<hhmmss>>.txt
:: 此日志记录了 PowerShell 命令的执行情况。

rem 其他应用程序日志: 通常位于 %APPDATA%\<应用程序名称>>\Logs 或 %PROGRAMDATA%\<应用程序名称>>\Logs
:: 系统诊断日志
:: Windows 错误报告日志: %WINDIR%\LiveKernelReports
::Windows 事件跟踪日志: %WINDIR%\Tracing


@rem 相关工具命令
rem everything 指定时间文件搜索
:: dm:2024/7/22-2024/9/13 *.exe|*.bat|*.vbs|*.jsp|*.jspx|*.dll|*.asp|*.aspx|*.ps1|*.vbs|*.ink|*.php

rem LogParser 日志分析命令
:: 显示全部日志 LogParser.exe -i:EVT -o:DATAGRID "SELECT * FROM D:\Software\LogParser\logs\Security.evtx"
:: 登录成功事件 LogParser.exe -i:EVT -o:DATAGRID  "SELECT *  FROM D:\Software\LogParser\logs\Security.evtx where EventID=4624"
:: 登录时间范围 LogParser.exe -i:EVT –o:DATAGRID  "SELECT *  FROM D:\Software\LogParser\logs\Security.evtx where TimeGenerated>>'2023-10-01 23:32:11' and TimeGenerated<'2023-10-26 23:34:00' and EventID=4624"
:: 登录失败事件 LogParser.exe -i:EVT –o:DATAGRID  "SELECT *  FROM D:\Software\LogParser\logs\Security.evtx where EventID=4625"
:: 登录成功用户名、IP LogParser.exe -i:EVT  –o:DATAGRID  "SELECT EXTRACT_TOKEN(Message,13,' ') as EventType,TimeGenerated as LoginTime,EXTRACT_TOKEN(Strings,5,'|') as Username,EXTRACT_TOKEN(Message,38,' ') as Loginip FROM D:\Software\LogParser\logs\Security.evtx where EventID=4624"
:: 系统历史开关机记录 LogParser.exe -i:EVT –o:DATAGRID  "SELECT TimeGenerated,EventID,Message FROM D:\Software\LogParser\logs\Security.evtx where EventID=6005 or EventID=6006"
:: 登录失败用户名进行聚合统计 LogParser.exe  -i:EVT "SELECT  EXTRACT_TOKEN(Message,13,' ')  as EventType,EXTRACT_TOKEN(Message,19,' ') as user,count(EXTRACT_TOKEN(Message,19,' ')) as Times,EXTRACT_TOKEN(Message,39,' ') as Loginip FROM D:\Software\LogParser\logs\Security.evtx where EventID=4625 GROUP BY Message"


rem 输出当前日期和时间
echo 运行时间: %date% %time% >> result\info.txt 2>nul
