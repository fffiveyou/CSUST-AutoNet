# CSUST AutoNet

长沙理工大学校园网 Windows 桌面工具，支持自动检测、Wi-Fi 重连、校园网认证及系统代理恢复。

## 功能

- 使用 Windows 已保存的校园 Wi-Fi 配置，默认 CSUST-Student。
- 检测间隔至少 30 秒，公网多探针至少两个成功才判定联网。
- 连续检测失败并确认校园登录页后，按用户设置自动认证。
- 每次仅提交一次；失败暂停自动提交，网络监测继续运行。
- 认证时临时关闭 Windows 系统代理，结束后恢复原设置，保持 Clash 运行。
- 系统托盘、后台运行和 Windows 登录自启动。
- 密码保存在 Windows Credential Manager，配置和日志位于 %LOCALAPPDATA%\CSUSTAutoNet。

## 使用

便携测试版见 [Releases](https://github.com/fffiveyou/CSUST-AutoNet/releases)。解压后运行 CSUSTAutoNet.exe，保留同目录的 _internal 文件夹。

填写账号密码并保存，按需启用自动认证。窗口关闭默认隐藏到托盘，完全退出请点击“退出程序”。避免同时运行多个实例。

## 开发

需要 Windows x64 和 Python 3.12。在项目目录执行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
# 后台启动
.\.venv\Scripts\python.exe main.py --background
# 测试与打包
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m PyInstaller build.spec
```

## 验证状态与限制

源码版曾在 Windows 10 x64、CSUST-Student、Clash for Windows 上实测通过。便携版通过程序入口与 Windows 凭据后端自检，完整用户验收尚未记录。历史测试运行在退出阶段出现挂起，因此不将进度条 100% 作为测试进程正常退出的证明。

其他代理软件为待支持占位项。校园网接口可能变化，当前认证入口使用 HTTPS 802 端口。发布包未签名。本项目非学校官方软件，仅用于本人有权使用的校园网账号。

不要上传账号密码、个人配置、HAR 抓包或日志。
