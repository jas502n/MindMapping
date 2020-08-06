# CobaltStrike

## 菜单栏

### Cobalt Strike 模块

-  New Connection-新连接
- Preferences-首选项

	- Cobalt Strike Configure

		- Tab Activity
		- Toolbar 工具栏
		- VNC Ports

			- 5000-9999

		- GUI Font (Restart)

	- Console

		- Font
		- Foreground
		- Background
		- Highlight

	- Fingerprints

		- 此面板是团队服务器SSL证书SHA-1哈希的列表。 您可以在此处删除受信任的哈希。

	- Graph

		- Selection

	- Reporting

		- Accent Color
		- Logo
		- Reports

	- Statusbar
	- Team Servers

		- Profiles

- Visualization 形式展示

	- Pivot Graph
	- Session Table

		- external
		- internal
		- listener
		- user
		- computer
		- note
		- process
		- pid
		- arch

			- x86
			- x64

		- last 心跳时间

	- Target Table

- VPN Interfaces 设置VPN接口
- Listeners 监听器

	- Payload

		- Beacon DNS

			- windows/beacon_dns/reverse_dns_txt

				- DNS中TXT类型传输数据

		- Beacon HTTP

			- windows/beacon_http/reverse_http

		- Beacon HTTPS

			- windows/beacon_https/reverse_https

				- 采用SSL加密传输数据

		- Beacon SMB

			- windows/beacon_bind_pipe

				- 命名管道 通过父Beacon 进行通信

		- Beacon TCP

			- windows/beacon_bind_tcp

		- External C2

			- windows/beacon_extc2

		- Foreign HTTP

			- windows/foreign/reverse_http

				- Session 派发 Metasploit、Empire

		- Foreign HTTPS

			- windows/foreign/reverse_https

- Script Manager-CNA脚本管理
- Close 关闭TeamServer连接

### View 模块

- Applications 被控机器的应用信息

	- external 内网
	- internal 外网
	- listener
	- user
	- computer
	- note
	- process

- Credentials 敏感 hash 和明文存储

	- user
	- password
	- realm
	- note
	- source
	- host
	- added

- Downloads 被控机器下载的文件

	- host
	- name
	- path
	- size
	- data

- Event Log 主机上线记录、聊天记录、操作记录

	- enent

- Keystrokes 键盘记录
- Proxy Pivots 代理模块

	- user
	- computer
	- pid
	- type
	- port
	- fhost
	- fport

- Screenshots 屏幕截图模块

	- user
	- computer
	- pid
	- when

- Script Console 脚本控制台

	- aggressor

- Targets 目标机器显示

	- address
	- name
	- note

- Web Log 访问的Web日志

### Attacks 模块

- Packages 模块

	- HTML Application

		- 调用其他语言的应用组件进行攻击测试

			- 可执行文件
			- Powershell
			- VBA

	- MS Office Macro

		- 生成基于Office病毒的 Payload 模块

	- Payload Generator 生成器

		- C
		- C#
		- COM Scriptlet
		- Java
		- Perl
		- PowerShell
		- PowerShell Command
		- Python
		- Raw
		- Ruby
		- Veil
		- VBA

	- Windows Executable

		- x86、x64

			- Windows DLL
			- Windows EXE
			- Windows Service EXE

	- Windows Executable (Stageless) 完整版

		- x86、x64

			- PowerShell
			- Raw
			- Windows EXE
			- Windows Service EXE
			- Windows DLL

- Web Drive-by 模块

	- Manage 管理器
	- Clone Site 克隆网站
	- Host File

		- 将指定的文件加载到Web目录中，支持修改Mime Type

	- Scripted Web Delivery (S)

		- x86、x64 自动生成基于Web攻击测试脚本命令

			- bitadmin
			- EXE
			- Powershell
			- Python

	- Signed Applet Attack

		- Java自签名程序进行钓鱼攻击测试（Applet权限）

	- Smart Applet Attack

		- 自动检测Java版本、跨平台、跨浏览器的攻击测试，禁用Java安全沙盒.   JDK <= 1.7.0_21

	- System Profiler

		- 浏览器加载check.js 获取系统版本、浏览器版本、Flash版本

- Spear Phish

### Reporting

- 0. Activity Report
- 1. Hosts Report
- 2. Indicators of Compromise
- 3. Sessions Report
- 4. Social Engineering Report
- 5. Tactics, Techniques, and Procedures
- Reset Data
- Export Data

### Help

- Homepage 主页

	- https://www.cobaltstrike.com/

- Support 支持

	- https://www.cobaltstrike.com/support

- Arsenal 武器库

	- https://www.cobaltstrike.com/scripts

- System Information 系统信息

	- Version:  4.1 (20200625) Licensed

- About

	- About.html

## 主机操作

### Interact

- Beacon Commands

	- argue

		- Spoof arguments for matching processes

	- blockdlls

		- Block non-Microsoft DLLs in child processes

	- browserpivot

		- Setup a browser pivot session

	- cancel

		- Cancel a download that's in-progress

	- cd

		- Change directory

	- checkin

		- Call home and post data

	- clear

		- Clear beacon queue

	- connect

		- Connect to a Beacon peer over TCP

	- covertvpn

		- Deploy Covert VPN client

	- cp

		- Copy a file

	- dcsync

		- Extract a password hash from a DC

	- desktop

		- View and interact with target's desktop

	- dllinject

		- Inject a Reflective DLL into a process

	- dllload

		- Load DLL into a process with LoadLibrary()

	- download

		- Download a file

	- downloads

		- Lists file downloads in progress

	- drives

		- List drives on target

	- elevate

		- Spawn a session in an elevated context

	- execute

		- Execute a program on target (no output)

	- execute-assembly

		- Execute a local .NET program in-memory on target

	- exit

		- Terminate the beacon session

	- getprivs

		- Enable system privileges on current token

	- getsystem

		- Attempt to get SYSTEM

	- getuid

		- Get User ID

	- hashdump

		- Dump password hashes

	- help

		- Help menu

	- inject

		- Spawn a session in a specific process

	- inline-execute

		- Run a Beacon Object File in this session

	- jobkill

		- Kill a long-running post-exploitation task

	- jobs

		- List long-running post-exploitation tasks

	- jump

		- Spawn a session on a remote host

	- kerberos_ccache_use

		- Apply kerberos ticket from cache to this session

	- kerberos_ticket_purge

		- Purge kerberos tickets from this session

	- kerberos_ticket_use

		- Apply kerberos ticket to this session

	- keylogger

		- Inject a keystroke logger into a process

	- kill

		- Kill a process

	- link

		- Connect to a Beacon peer over a named pipe

	- logonpasswords

		- Dump credentials and hashes with mimikatz

	- ls

		- List files

	- make_token

		- Create a token to pass credentials

	- mimikatz

		- Runs a mimikatz command

	- mkdir

		- Make a directory

	- mode dns

		- Use DNS A as data channel (DNS beacon only)

	- mode dns-txt

		- Use DNS TXT as data channel (DNS beacon only)

	- mode dns6

		- Use DNS AAAA as data channel (DNS beacon only)

	- mv

		- Move a file

	- net

		- Network and host enumeration tool

	- note

		- Assign a note to this Beacon 

	- portscan

		- Scan a network for open services

	- powerpick

		- Execute a command via Unmanaged PowerShell

	- powershell

		- Execute a command via powershell.exe

	- powershell-import

		- Import a powershell script

	- ppid

		- Set parent PID for spawned post-ex jobs

	- ps

		- Show process list

	- psinject

		- Pass-the-hash using Mimikatz

	- pth

		- Pass-the-hash using Mimikatz

	- pwd

		- Print current directory

	- reg

		- Query the registry

	- remote-exec

		- Run a command on a remote host

	- rev2self

		- Revert to original token

	- rm

		- Remove a file or folder

	- rportfwd

		- Setup a reverse port forward

	- run

		- Execute a program on target (returns output)

	- runas

		- Execute a program as another user

	- runasadmin

		- Execute a program in an elevated context

	- runu

		- Execute a program under another PID

	- screenshot

		- Take a screenshot

	- setenv

		- Set an environment variable

	- shell

		- Execute a command via cmd.exe

	- shinject

		- Inject shellcode into a process

	- shspawn

		- Spawn process and inject shellcode into it

	- sleep

		- Set beacon sleep time

	- socks

		- Start SOCKS4a server to relay traffic

	- socks stop

		- Stop SOCKS4a server

	- spawn

		- Spawn a session

	- spawnas

		- Spawn a session as another user

	- spawnto

		- Set executable to spawn processes into

	- spawnu

		- Spawn a session under another process

	- ssh

		- Use SSH to spawn an SSH session on a host

	- ssh-key

		- Use SSH to spawn an SSH session on a host

	- steal_token

		- Steal access token from a process

	- timestomp

		- Apply timestamps from one file to another

	- unlink

		- Disconnect from parent Beacon

	- upload

		- Upload a file

### Access

- Dump Hashes
- Elevate

	- svc-exe
	- uac-token-duplication

- Golden Ticket

	- User
	- Domain
	- Domain SID
	- KRBTGT Hash

- Make Token

	- User
	- Password
	- Doamin

- One-liner

	- PowerShell One-liner 

- Run Mimikatz

	- mimikatz's sekurlsa::logonpasswords

- Spawn As

	- User
	- Password
	- Domain
	- Listener

### Explore

- Brower Pivot

	- Proxy Server Port

- Desktop (VNC)
- File Browser
- Net View
- Port Scan
- Process List
- Screenshot

### Pivoting

- SOCKS Server

	- Proxy Server Port

- Listener

	- Name
	- Payload
	- Listen Host
	- Listen Port
	- Session

- Deploy VPN

	- Local Interface
	- Clone host MAC address

		- https://www.cobaltstrike.com/help-covert-vpn

	- Deploy

### Spawn

- Choose a payload

### Session

- Note
- Color
- Remote
- Sleep
- Exit

*XMind: ZEN - Trial Version*