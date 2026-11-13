# CSUST AutoNet v0.1.0

Windows x64 便携测试版，发布日期：2026-09-23。

## 使用方法

1. 解压 `CSUST-AutoNet-v0.1.0-windows-x64.zip`，不要只从 ZIP 内直接运行。
2. 打开解压后的 `CSUSTAutoNet` 文件夹，运行 `CSUSTAutoNet.exe`。
3. 发布版沿用 `%LOCALAPPDATA%\CSUSTAutoNet` 中的非敏感配置和 Windows 凭据管理器中的密码，不会把密码打进发布包。
4. 首次切换到发布版后，在程序中再次点击“保存设置”；若已启用 Windows 开机启动，这会把启动项从开发环境更新为发布版 EXE。
5. 不要同时运行源码开发版和发布版。

## 已验证

- Windows 10 x64 启动与系统托盘后台运行。
- `CSUST-Student` Wi-Fi 自动重连。
- 连续检测确认校园网登录页后仅自动提交一次。
- 校园网认证接口 HTTP 200、直连公网复检及 Windows 系统代理精确恢复。
- Clash for Windows 保持运行，仅临时关闭并恢复 Windows 系统代理。
- Windows 登录后后台自启动。
- PyInstaller Qt 启动与 Windows Credential Manager 后端自检。

## 注意

- 本程序未进行代码签名，Windows SmartScreen 可能提示“未知发布者”。请只使用本目录内附带 SHA-256 校验值的文件。
- 当前只对长沙理工大学 `CSUST-Student` 与 Clash for Windows 组合完成实机验收。
- 自动认证失败后会暂停提交，但网络监测继续运行；可在主界面手动重试。
- 本版本是 onedir 便携包，必须保留 `CSUSTAutoNet.exe` 与 `_internal` 文件夹的相对位置。

## 校验值

`CSUST-AutoNet-v0.1.0-windows-x64.zip`

SHA-256: `9482CA2674F696C6D6DAD0C076C3CF8069E93F1B433329B2DA67B9FCF789D3E3`
