## Beacon Commands

```
===============

    Command                   Description
    -------                   -----------
    argue                     Spoof arguments for matching processes
    blockdlls                 Block non-Microsoft DLLs in child processes
    browserpivot              Setup a browser pivot session
    cancel                    Cancel a download that's in-progress
    cd                        Change directory
    checkin                   Call home and post data
    clear                     Clear beacon queue
    connect                   Connect to a Beacon peer over TCP
    covertvpn                 Deploy Covert VPN client
    cp                        Copy a file
    dcsync                    Extract a password hash from a DC
    desktop                   View and interact with target's desktop
    dllinject                 Inject a Reflective DLL into a process
    dllload                   Load DLL into a process with LoadLibrary()
    download                  Download a file
    downloads                 Lists file downloads in progress
    drives                    List drives on target
    elevate                   Spawn a session in an elevated context
    execute                   Execute a program on target (no output)
    execute-assembly          Execute a local .NET program in-memory on target
    exit                      Terminate the beacon session
    getprivs                  Enable system privileges on current token
    getsystem                 Attempt to get SYSTEM
    getuid                    Get User ID
    hashdump                  Dump password hashes
    help                      Help menu
    inject                    Spawn a session in a specific process
    inline-execute            Run a Beacon Object File in this session
    jobkill                   Kill a long-running post-exploitation task
    jobs                      List long-running post-exploitation tasks
    jump                      Spawn a session on a remote host
    kerberos_ccache_use       Apply kerberos ticket from cache to this session
    kerberos_ticket_purge     Purge kerberos tickets from this session
    kerberos_ticket_use       Apply kerberos ticket to this session
    keylogger                 Inject a keystroke logger into a process
    kill                      Kill a process
    link                      Connect to a Beacon peer over a named pipe
    logonpasswords            Dump credentials and hashes with mimikatz
    ls                        List files
    make_token                Create a token to pass credentials
    mimikatz                  Runs a mimikatz command
    mkdir                     Make a directory
    mode dns                  Use DNS A as data channel (DNS beacon only)
    mode dns-txt              Use DNS TXT as data channel (DNS beacon only)
    mode dns6                 Use DNS AAAA as data channel (DNS beacon only)
    mv                        Move a file
    net                       Network and host enumeration tool
    note                      Assign a note to this Beacon       
    portscan                  Scan a network for open services
    powerpick                 Execute a command via Unmanaged PowerShell
    powershell                Execute a command via powershell.exe
    powershell-import         Import a powershell script
    ppid                      Set parent PID for spawned post-ex jobs
    ps                        Show process list
    psinject                  Execute PowerShell command in specific process
    pth                       Pass-the-hash using Mimikatz
    pwd                       Print current directory
    reg                       Query the registry
    remote-exec               Run a command on a remote host
    rev2self                  Revert to original token
    rm                        Remove a file or folder
    rportfwd                  Setup a reverse port forward
    run                       Execute a program on target (returns output)
    runas                     Execute a program as another user
    runasadmin                Execute a program in an elevated context
    runu                      Execute a program under another PID
    screenshot                Take a screenshot
    setenv                    Set an environment variable
    shell                     Execute a command via cmd.exe
    shinject                  Inject shellcode into a process
    shspawn                   Spawn process and inject shellcode into it
    sleep                     Set beacon sleep time
    socks                     Start SOCKS4a server to relay traffic
    socks stop                Stop SOCKS4a server
    spawn                     Spawn a session 
    spawnas                   Spawn a session as another user
    spawnto                   Set executable to spawn processes into
    spawnu                    Spawn a session under another process
    ssh                       Use SSH to spawn an SSH session on a host
    ssh-key                   Use SSH to spawn an SSH session on a host
    steal_token               Steal access token from a process
    timestomp                 Apply timestamps from one file to another
    unlink                    Disconnect from parent Beacon
    upload                    Upload a file
```

#### zh-cn

```
argue           进程参数欺骗
blockdlls       阻止子进程加载非微软签名的dll
browserpivot        Setup a browser pivot session
cancel          将取消正在进行的下载任务
cd          切换目录
checkin         Call home and post data
covertvpn       Deploy Covert VPN client
clear           清屏
connect         通过Tcp连接到一个Beacon会话
cp          复制文件
dcsync          从DC提取密码哈希
desktop         VNC远程桌面
dllinject       反射dll进程注入
dllload         LoadLibrary()函数进程注入
download        下载文件
downloads       列出正在进行的文件下载任务
drives          列出目标上的驱动器
elevate         Spawn a session in an elevated context
execute         在目标上执行程序（无回显）
execute-assembly    内存加载执行.NET程序集
exit            退出beacon
getprivs        Enable system privileges on current token
getsystem       尝试获取System权限
getuid          获取用户ID
hashdump        转储密码哈希
help            Help menu
inject          在指定进程中生成一个会话
inline-execute      在会话中执行Beacon Object File (BOF)
jobs            List long-running post-exploitation tasks
jobkill         Kill a long-running post-exploitation task
jump            在远程主机上生成一个会话
kerberos_ccache_use Apply kerberos ticket from cache to this session
kerberos_ticket_purge   Purge kerberos tickets from this session
kerberos_ticket_use Apply kerberos ticket to this session
keylogger       将键盘记录器注入一个进程
kill            结束一个进程
link            Connect to a Beacon peer over a named pipe
logonpasswords      Dump credentials and hashes with mimikatz
ls          显示文件
make_token      Create a token to pass credentials
mimikatz        执行mimikatz命令
mkdir           创建目录
mode dns        Use DNS A as data channel (DNS beacon only)
mode dns6       Use DNS AAAA as data channel (DNS beacon only)
mode dns-txt        Use DNS TXT as data channel (DNS beacon only)
mv          移动文件
net         net命令
note            备注Beacon会话       
portscan        Scan a network for open services
powerpick       Execute a command via Unmanaged PowerShell
powershell      通过powershell.exe执行命令
powershell-import   导入Powershell脚本
ppid            Set parent PID for spawned post-ex jobs
ps          显示进程列表
psinject        在指定进程中执行PowerShell命令
pth         Pass-the-hash using Mimikatz
pwd         显示当前所在目录
reg         Query the registry
remote-exec     在远程主机上执行命令
rev2self        设置端口转发
rm          删除文件
rportfwd        Setup a reverse port forward
run         在目标上执行程序（输出回显）
runas           以其他用户权限执行程序
runasadmin      Execute a program in an elevated context
runu            Execute a program under another PID
screenshot      截屏
setenv          设置环境变量
shell           通过cmd执行命令
shinject        shellcode注入
shspawn         创建一个进程并注入shellcode
sleep           设置beacon睡眠时间
socks           启动SOCKS4代理
socks stop      停止SOCKS4代理
spawn           派生会话
spawnas         以其他用户身份生成一个会话
spawnto         Set executable to spawn processes into
spawnu          在指定进程中生成一个新会话
ssh         使用SSH连接到远程主机
ssh-key         使用SSH密钥连接到远程主机
steal_token     从进程中窃取访问令牌
timestomp       复制指定文件时间戳到其他文件
unlink          断开与父Beacon的连接
upload          上传文件
```

## Fix watemark

`/common/ListenerConfig.class`

```
    public String pad(String var1, int var2) {
        StringBuffer var3 = new StringBuffer();
        var3.append(var1);

        while(var3.length() < var2) {
            if (this.watermark == 0) {
                var3.append("5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\u0000");
            } else {
                var3.append((char)CommonUtils.rand(255));
            }
        }

        return var3.toString().substring(0, var2);
    }
```

#### Change

```
    public String pad(String var1, int var2) {
        StringBuffer var3 = new StringBuffer();
        var3.append(var1);

        while(var3.length() < var2) {
            if (this.watermark != 0) {
                var3.append((char)CommonUtils.rand(255));
            } 
        }

        return var3.toString().substring(0, var2);
    }

```
