# Windows 利用 ansible 实现自动更新 Tomcat or Anything else

## 使用说明

### 1. Windows Server 配置要求
``` shell
# 设置 HTTP 服务为自动启动
Set-Service -Name HTTP -StartupType Automatic

# 启动 HTTP 服务
Start-Service -Name HTTP

# 启动 WinRM 服务
Start-Service -Name WinRM 

# 配置 WinRM
$ansibleconfigurl = "https://gh-proxy.com/raw.githubusercontent.com/ansible/ansible-documentation/refs/heads/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$ansibleconfig = "$env:temp\ConfigureRemotingForAnsible.ps1"
(New-Object -TypeName System.Net.WebClient).DownloadFile($ansibleconfigurl, $ansibleconfig)
powershell.exe -ExecutionPolicy ByPass -File $ansibleconfig
```

### 2. Linux 主机
``` shell
# 安装 ansible
yum install ansible

# 安装 python2-winrm
yum install python2-winrm.noarch
```

### 3. 运行
``` shell
# 配置文件 mode 用于指定启动模式，可选值: watch, server (默认 "server")
# server 模式下，启动服务端，提供 web 界面，用于上传 zip 文件
# watch 模式下，启动监控程序，监控指定目录，指定时间范围，收集变化文件
autoupdater:
  mode: "watch" # 启动模式可选值: watch, server (默认 "server")
  server:
    port: 8333 # 服务端口
    password: "123456" # 服务密码
    upload_path: "/home/autoupdater/class/" # 上传路径
    ansible:
      host_config:
        path: "/etc/ansible/hosts" # 主机配置文件路径
        include_group:
          - "win_css_serv_prod" # 主机组
          - "win_css_serv_test" # 主机组
      playbook_config:
        path: "/home/ansible-playbook/win_auto_update_tomcat.yml" # 剧本文件路径
        forks: 1 # 并发数
  watch:
    path: "D:\\linux.do" # 监听目录路径
    exclude: "*.tmp,*.log" # 排除的文件支持正则，多个模式用逗号分隔 (例如: *.tmp,*.log)
    time_before: "2024-08-26 00:00" # 监控时间范围
    time_after: "2026-02-26 08:00" # 监控时间范围

# 运行 windows
./autoupdater.exe 

# 运行 linux
./autoupdater
```

### 4. ansible 配置
``` shell
 
# 配置 ansible 的 hosts 文件
[webservers:vars]
ansible_ssh_user=root
ansible_ssh_pass=abc123!@#


# 主机组命名规范
# 主机组名称为：_prod 或 _test 结尾，用于区分测试跟生产环境
[win_serv_prod]
192.168.1.121 ansible_user=ADMINISTRATOR ansible_ssh_pass='**'
192.168.1.122 ansible_user=ADMINISTRATOR ansible_ssh_pass='**'
192.168.1.165 ansible_user=Administrator ansible_ssh_pass='#@!'
192.168.1.127 ansible_user=ADMINISTRATOR ansible_ssh_pass='&%'

[win_serv_test]
1.1.1.1 ansible_user=ADMINISTRATOR ansible_ssh_pass=',.'  


[win_serv_prod:vars]
ansible_port=5986
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
ansible_winrm_transport=basic
ansible_winrm_scheme=https
ansible_winrm_server_cert_validation=ignore
ansible_winrm_operation_timeout_sec=60
ansible_winrm_read_timeout_sec=70

[win_serv_test:vars]
ansible_port=5986
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
ansible_winrm_transport=basic
ansible_winrm_scheme=https
ansible_winrm_server_cert_validation=ignore
ansible_winrm_operation_timeout_sec=60
ansible_winrm_read_timeout_sec=70
```

### 5. ansible 的 playbook
``` yml
---
- name: 关闭指定端口的进程
  hosts: windows
  gather_facts: no
  vars:
    ansible_connection: winrm
    ansible_winrm_transport: basic
    ansible_winrm_server_cert_validation: ignore
    port_configs:
      123.456.789.100:
        - port: 80
          tomcat_path: "E:\\java\\apache-tomcat-7.0.82-windows-x64\\apache-tomcat-7.0.82"

  tasks:
    - name: 复制要更新的class到tomcat
      win_copy:
        src: "/home/autoupdater/class/"
        dest: "{{ item.tomcat_path }}\\webapps\\jydweb"
        force: yes
      loop: "{{ port_configs[inventory_hostname] | default([]) }}"

    - name: 查找并关闭指定端口的进程
      win_shell: |
        $port = {{ item.port }}
        $tomcatPath = "{{ item.tomcat_path }}"
        $processId = (Get-NetTCPConnection -LocalPort $port).OwningProcess
        if ($processId) {
            Stop-Process -Id $processId -Force
            "已终止占用端口 $port 的进程，进程ID为 $processId"
            "对应的Tomcat目录为: $tomcatPath"
        } else {
            "没有找到占用端口 $port 的进程"
        }
      register: result
      loop: "{{ port_configs[inventory_hostname] | default([]) }}"

    - name: 删除已存在的Tomcat启动计划任务
      win_shell: schtasks /Delete /TN "StartTomcat_{{ item.port }}" /F
      loop: "{{ port_configs[inventory_hostname] | default([]) }}"
      ignore_errors: yes

    - name: 创建启动Tomcat的计划任务
      win_scheduled_task:
        name: "StartTomcat_{{ item.port }}"
        description: "Start Tomcat on port {{ item.port }}"
        actions:
        - path: cmd.exe
          arguments: '/c "{{ item.tomcat_path }}\\bin\\startup.bat"'
        triggers: []
        run_level: highest
        logon_type: interactive_token
        state: present
      loop: "{{ port_configs[inventory_hostname] | default([]) }}"
      register: tomcat_task_result

    - name: 运行Tomcat启动任务
      win_shell: schtasks /Run /TN "StartTomcat_{{ item.port }}"
      loop: "{{ port_configs[inventory_hostname] | default([]) }}"
      when: tomcat_task_result.changed

    - name: 显示结果
      debug:
        var: result
```
 

### 6. 自动收集变化文件
``` shell
autoupdater.exe -watch D:\path\to\watch 
```
 
### 7. 帮助
``` shell
autoupdater.exe -h
```
### 8. 实践
``` shell
autoupdater.exe -watch D:\path\to\watch # 输入 zip 收集变化文件
# 在浏览器中打开 http://localhost:8333/
# 输入密码
# 上传 zip 文件
# 点击 deploy 按钮，更新
``` 

