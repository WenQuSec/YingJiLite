# 应急轻 YingJiLite

**问渠安全实验室 WenQuSec 出品 · Windows x64 · MIT 开源**

一键只读取证，围绕异常对象给出文件落地、权限维持、进程与网络关联，以及可继续核验的精确位置。单个 EXE，报告生成到桌面。

[组织主仓库](https://github.com/WenQuSec/YingJiLite) · [个人副本](https://github.com/yishuizhe/YingJiLite)

[下载 Windows 单 EXE](https://github.com/WenQuSec/YingJiLite/releases/latest)

## 目录

[使用](#使用) · [报告怎么读](#报告怎么读) · [检测范围](#检测范围) · [源码构建](#源码构建) · [测试](#测试) · [边界与隐私](#边界与隐私) · [许可](#许可)

## 使用

1. Windows 10/11 x64，安装系统自带的 Windows PowerShell 5.1 与 .NET Framework 4.8。
2. 以管理员身份运行 `YingJiLite.exe`，选择回溯时间，点击检查。检查通常需要数分钟，耗时随文件数量、权限和系统负载变化。
3. 打开桌面 `应急轻报告\IR-时间-随机标识\report.html`。

交付时只需 EXE。运行中内嵌脚本在进程内执行，不释放 PS1、辅助 DLL，不启动 powershell.exe，不在现场动态编译 C#。报告目录仍会产生 HTML、JSON、ETL 与日志，它们是取证成果。

命令行检查（默认回溯 72 小时）：

```powershell
.\YingJiLite.exe --scan C:\IR-Reports
```

已有本工具生成的证据可以离线回放；这是开发与复核入口，日常一键检查无需提供样本：

```powershell
.\YingJiLite.exe --scan C:\IR-Replay C:\Evidence\evidence.json
```

## 报告怎么读

| 状态 | 含义 | 下一步 |
| --- | --- | --- |
| 红色 | 高风险证据或多项相关证据组合 | 优先保全证据，按对象核验文件、启动配置、进程与通信 |
| 黄色 | 待核实异常或关键采集不完整 | 查看缺口与核验命令，补权限或日志后复查 |
| 绿色 | 本次核心检查完成且未发现对应异常 | 保留报告；不代表不存在未知威胁 |

首页看概要和优先对象，对象页看“文件在哪里、谁启动它、如何维持、连接到哪里”。注册表给出键与值名，服务/任务给出名称及实际配置，通信区区分连接、DNS、离线静态地址和候选 C2。只有具备证据的关系才用于链路，候选关系会标注不确定性。

目录中的 `evidence.json` 是原始采集，`analysis.json` 是关联结果，`response-plan.json` 是对象核验计划，`network-evidence.json` 是独立网络证据，`manifest.json` 保存输出文件的 SHA-256。报告隐藏一般正常项，但原始证据保留用于复核。

## 检测范围

- 进程路径、命令行、启动时间与模块；验证进程身份，降低 PID 重用误关联。
- 注册表启动项、服务、计划任务、WMI 永久事件订阅及常见加载位置。
- 实际加载 DLL、隐藏目录、签名摘要异常、伪装或编码 PE、脚本执行线索。
- 实时 TCP/UDP、DNS 缓存与 DNS/AFD ETW 观察；断网时也保留能观察到的失败 DNS。
- 非映像可执行内存与线程起点、主映像差异、已有 USN 与执行/崩溃历史。
- 挖矿参数、可疑执行、历史安全告警及可核验的对象关联。

采用通用证据与行为规则，不内置本次样本名称、哈希或 C2答案。缺少运行、通信或历史日志时，无法补出不存在的证据。DNS缓存不含进程归属；静态地址不等同已成功连接的C2。

## 源码构建

需要 Windows x64、.NET Framework 4.8、Windows PowerShell 5.1、Python 3.10+。无需 NuGet、额外 Python 包或其他版本的本项目。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

输出到新的 `build-时间-随机标识` 目录。只分发 `YingJiLite.exe`；`payload.bin` 是构建中间资源，已嵌入 EXE。脚本拒绝复用已有构建目录，保留所有输入和中间文件。

`src/scripts` 是取证与规则源码，`src/native` 是预编译只读探测器，`src/Collector.cs` 创建进程内 PowerShell 运行空间，`assets` 包含界面、原始盾牌图标与实验室标识。压缩用于减小体积，不提供保密或防逆向保证。

## 测试

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\smoke.ps1 -Binary .\build-目录\YingJiLite.exe
```

测试使用合成进程、服务、注册表与网络证据，验证关联到准确对象、报告生成、清单校验，以及不释放代码文件。测试不执行恶意程序、不连接测试 C2、不改变系统启动配置。Windows CI 会独立构建并运行该测试。

## 边界与隐私

仅采集和给出人工核验计划，不自动删除、隔离、结束进程、清日志或修改服务/注册表。ETW 使用本工具创建的观察会话，结束时停止自己的会话。Windows 签名验证组件可能按系统策略联网；本工具无云端上传接口。

无法保证识别所有病毒、银狐、后门或无文件攻击，也不提供勒索解密与恢复。内核隐匿、已消失的网络记录、日志未启用和权限受限都可能造成漏检。启发式异常需人工核实，合法插件、调试器和运维脚本可能命中。

报告包含主机、账户、路径、命令和通信数据，请在本地保管，公开前脱敏。本仓库不包含真实应急报告、恶意样本、虚拟机、账户凭据或个人数据。

## 许可

源码使用 [MIT](LICENSE)。Lucide 图标使用 ISC，见 [第三方说明](THIRD_PARTY_NOTICES.md)。实验室名称与标识用于标示项目来源，不表示对第三方修改版背书。
