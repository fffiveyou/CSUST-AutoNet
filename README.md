# CSUST AutoNet

为解决长沙理工大学校园网使用中**容易掉线、开机后需要手动连接和登录认证**的问题，开发的 Windows 桌面自动联网工具。

完成首次设置后，CSUST AutoNet 可以在后台定时检测网络：校园 Wi-Fi 断开时尝试重新连接，需要登录时自动完成校园网认证；开启 Windows 登录自启动后，开机登录系统即可自动运行，减少反复连接 Wi-Fi、打开登录页面和输入账号密码的操作。

本工具用于在掉线后尝试恢复连接，不能消除校园网本身的故障或保证网络始终不断线。

供 AI 工具读取的项目摘要与文档导航：[llms.txt](llms.txt)。

## 适用场景

- **校园网经常掉线**：自动检测网络状态，尝试重连校园 Wi-Fi，并在确认需要认证后自动登录。
- **每次开机都要手动联网**：启用自启动、Wi-Fi 自动连接和自动认证后，在登录 Windows 后自动处理联网流程。
- **使用 Clash 时校园网认证受代理影响**：认证期间临时关闭 Windows 系统代理，完成后按设置恢复，无需退出 Clash。

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

首次使用：

1. 在 Windows 中连接一次校园 Wi-Fi，保存网络配置（默认名称为 `CSUST-Student`）。
2. 打开软件，填写校园网账号和密码，点击“保存设置”。
3. 勾选“检测前自动连接校园 Wi-Fi”和“启用自动认证”。如需开机后自动联网，再勾选“Windows 开机自动运行”，然后保存设置。
4. 使用“立即检测”检查网络；需要登录时可用“立即认证”验证账号及认证流程。确认正常后，保持软件在后台运行即可。

窗口关闭默认隐藏到托盘，完全退出请点击“退出程序”。避免同时运行多个实例。自启动在登录 Windows 后生效；自动重连需要处于校园 Wi-Fi 覆盖范围内，并已保存对应的网络配置。

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

若默认 pytest 临时目录因切换 Windows 用户或运行环境而出现权限错误，可指定新的独立临时目录（每次使用不同名称）：

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp "$env:TEMP\csust-tests-$([guid]::NewGuid().ToString('N'))"
```

## 验证状态与限制

源码版曾在 Windows 10 x64、CSUST-Student、Clash for Windows 上实测通过。已发布的 v0.1.0 便携版通过程序入口与 Windows 凭据后端自检，完整用户验收尚未记录。

后续源码增加了后台任务安全退出、认证会话清理和长期运行内存限制。历史测试退出挂起在本轮独立临时目录中未复现；离线回归通过并确认进程退出码为 0，包括检测/认证进行中退出和任务异常场景。测试不访问真实校园网、不提交真实凭据、不修改系统代理。上述源码修复尚未包含在 v0.1.0 下载包中，仍需新版便携包与真实网络验收。

其他代理软件为待支持占位项。校园网接口可能变化，当前认证入口使用 HTTPS 802 端口。发布包未签名。本项目非学校官方软件，仅用于本人有权使用的校园网账号。

不要上传账号密码、个人配置、HAR 抓包或日志。
