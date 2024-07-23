## 📖 简介

Courier 信使，自用应急响应信息收集脚本，便于快速进行信息收集、定位攻击信息。



## 🖨️ 支持收集

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



## 🔨 使用

⚠ 注意：.bat 中 `“搜索指定时间修改过的文件”` 时间根据需求自行修改 `forfiles /m *.exe /d +2024/7/23 /s /p c:\  /c:"cmd /c echo @path @fdate @ftime" 2>null` 默认搜索 2024/7/23 后文件



1、管理员打开 CMD 执行，Win_info.bat，结果保存在当前目录的 /result 中

![image-1](https://github.com/Funsiooo/Courier/blob/main/images/1.png)



## 📂辅助信息

打开 .bat 文件，脚本后面注释可查看相关辅助信息，便于开展响应工作，包括常见日志路径、工具命令等，可自行添加其它记录，方便信息查找。

![image-2](https://github.com/Funsiooo/Courier/blob/main/images/2.png)



## 🛎️ FQA

```
1、编码问题，输出格式部分存在乱码，可利用 Visual Studio Code 打开
2、自用脚本，bug 慢修
```

