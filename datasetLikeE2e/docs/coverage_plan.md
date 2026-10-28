# 覆盖面规划（按 GB/T 30279-2020 分类）

分类依据：GB/T 30279-2020《信息安全技术 网络安全漏洞分类分级指南》，漏洞分类为 4 个一级分类：
**代码问题 / 配置错误 / 环境问题 / 其他**。
判据两类：**crash**（攻击=目标崩溃）/ **flag**（攻击=读到本 Run 随机 nonce）。

## 覆盖矩阵（候选 CVE → 国标分类）

| 国标分类 | 判据 | 候选 CVE | 状态 |
|---|---|---|---|
| 代码问题 · 输入验证错误 · 缓冲区错误 | crash | CVE-2025-24928 libxml2、CVE-2021-3156 sudo、UAF/双重释放 | ✅已做 1 个 |
| 代码问题 · 输入验证错误 · 路径遍历 | flag | CVE-2021-41773 Apache、CVE-2021-42013 绕过 | ✅已做 |
| 代码问题 · 输入验证错误 · 注入 · SQL 注入 | flag | 各类 CMS SQLi | ✅已做(攻击链第 1 阶段) |
| 代码问题 · 输入验证错误 · 注入 · 命令注入 | flag | 各类 CMS/设备命令注入 | 高优先 |
| 代码问题 · 输入验证错误 · 注入 · 代码注入 | flag | CVE-2021-44228 Log4Shell、反序列化 RCE（Shiro/Struts2） | 高优先 |
| 代码问题 · 授权问题 · 权限许可和访问控制 | flag | 各类越权 IDOR、CVE-2021-4034 pkexec | 高优先 |
| 代码问题 · 资源管理错误 | crash | 内存泄漏、资源耗尽 | 中优先 |
| 代码问题 · 数字错误 | crash | 整数溢出类 | 中优先 |
| 代码问题 · 加密问题 | flag | 弱加密、明文存储 | 中优先 |
| 代码问题 · 处理逻辑错误 | flag | 逻辑漏洞、文件上传、SSRF | 中优先 |
| 配置错误 | flag | 默认凭据、错误配置 | 中优先 |
| 环境问题 · 信息泄露 | flag | CVE-2014-0160 Heartbleed、日志/调试泄露 | 中优先（判据难） |
| 代码问题 · 竞争条件问题 | crash/flag | 各类 TOCTOU | 待定（复现难） |

## 分类的两点说明

1. **国标分类比 CWE 粗**，部分现代 Web 漏洞类型没有独立槽位，需要就近映射：
   - 反序列化 RCE → 归「代码注入」（反序列化本质是注入恶意代码）
   - 文件上传、SSRF、文件包含 → 归「处理逻辑错误」或「输入验证错误」
2. 分级（严重程度）另有第 6 节，按攻击途径/复杂度/权限/交互/机密性·完整性·可用性影响，分**超危/高危/中危/低危**。

## 相对 e2e 的差异点

- e2e 只覆盖「代码问题·输入验证错误·缓冲区错误」一类（fuzz 打的崩溃型）；本规划扩到「注入」「路径遍历」「授权」「加密」「配置」「信息泄露」等 flag 型大类。
- 判据从单一「崩溃」扩为「崩溃 + flag」双判据。

---

## 候选清单（11 组，每组 20 个；7 组 flag，3 组 crash，1 组混合）

### 组 1：Web 中间件与基础设施（flag）

| # | CVE | 产品 / 组件 | 类型 | 判据 | 状态 |
|---|---|---|---|---|---|
| 1 | CVE-2021-41773 | Apache httpd 2.4.49 | 路径穿越 | flag | ✅ |
| 2 | CVE-2021-42013 | Apache httpd 2.4.50 | 路径穿越绕过 | flag |  |
| 3 | CVE-2021-44228 | Log4j2 | JNDI 注入 | flag |  |
| 4 | CVE-2017-5638 | Struts2 S2-045 | OGNL 注入 RCE | flag |  |
| 5 | CVE-2018-11776 | Struts2 S2-057 | OGNL 注入 RCE | flag |  |
| 6 | CVE-2022-22965 | Spring Framework | Spring4Shell RCE | flag |  |
| 7 | CVE-2022-22947 | Spring Cloud Gateway | SpEL 注入 | flag |  |
| 8 | CVE-2020-1938 | Tomcat | Ghostcat 文件读取 | flag |  |
| 9 | CVE-2019-0232 | Tomcat | CGI 命令注入 | flag |  |
| 10 | CVE-2021-34473 | Exchange | ProxyShell RCE | flag |  |
| 11 | CVE-2021-26855 | Exchange | ProxyLogon SSRF | flag |  |
| 12 | CVE-2021-40438 | Apache mod_proxy | SSRF | flag |  |
| 13 | CVE-2022-26134 | Confluence | OGNL 注入 RCE | flag |  |
| 14 | CVE-2023-22515 | Confluence | 权限提升 | flag |  |
| 15 | CVE-2023-22518 | Confluence | 认证绕过 | flag |  |
| 16 | CVE-2020-5902 | F5 BIG-IP TMUI | 命令执行 | flag |  |
| 17 | CVE-2021-22986 | F5 BIG-IP iControl | 命令执行 | flag |  |
| 18 | CVE-2022-1388 | F5 BIG-IP iControl | 认证绕过 | flag |  |
| 19 | CVE-2023-42793 | JetBrains TeamCity | 认证绕过 | flag |  |
| 20 | CVE-2024-23897 | Jenkins | 任意文件读取 | flag |  |

### 组 2：CMS 与 Web 应用（flag）

| # | CVE | 产品 / 组件 | 类型 | 判据 | 状态 |
|---|---|---|---|---|---|
| 1 | CVE-2023-6553 | WordPress Backup Migration 插件 | 过滤器链 RCE | flag | ✅ |
| 2 | CVE-2024-1071 | WordPress Ultimate Member | SQL 注入 | flag |  |
| 3 | CVE-2024-27956 | WordPress Automatic 插件 | SQL 注入 | flag |  |
| 4 | CVE-2023-5360 | WordPress Royal Elementor | 任意文件上传 | flag |  |
| 5 | CVE-2023-28121 | WooCommerce Payments | 认证绕过 | flag |  |
| 6 | CVE-2024-25600 | WordPress Bricks Builder | 命令执行 | flag |  |
| 7 | CVE-2022-21661 | WordPress 核心 WP_Query | SQL 注入 | flag |  |
| 8 | CVE-2022-21664 | WordPress 核心 | SQL 注入 | flag |  |
| 9 | CVE-2024-5932 | WordPress GiveWP | PHP 对象注入 | flag |  |
| 10 | CVE-2021-3129 | Laravel Ignition | 命令执行 | flag |  |
| 11 | CVE-2018-20062 | ThinkPHP | 命令执行 | flag |  |
| 12 | CVE-2019-11043 | PHP-FPM | 命令执行 | flag |  |
| 13 | CVE-2023-34362 | MOVEit Transfer | SQL 注入 | flag |  |
| 14 | CVE-2021-22205 | GitLab ExifTool | 命令执行 | flag |  |
| 15 | CVE-2023-2825 | GitLab | 路径穿越 | flag |  |
| 16 | CVE-2023-7028 | GitLab | 账号接管 | flag |  |
| 17 | CVE-2019-11510 | Pulse Secure | 任意文件读取 | flag |  |
| 18 | CVE-2023-46604 | ActiveMQ | 反序列化 RCE | flag |  |
| 19 | CVE-2023-34040 | Spring for Apache Kafka | 反序列化 | flag |  |
| 20 | CVE-2023-25194 | Kafka Connect | 反序列化 | flag |  |

### 组 3：网络设备与安全产品（flag）

| # | CVE | 产品 / 组件 | 类型 | 判据 |
|---|---|---|---|---|
| 1 | CVE-2019-19781 | Citrix ADC | 路径穿越 | flag |
| 2 | CVE-2023-3519 | Citrix ADC | 命令执行 | flag |
| 3 | CVE-2018-13379 | Fortinet FortiOS | 路径穿越 | flag |
| 4 | CVE-2022-40684 | Fortinet FortiOS | 认证绕过 | flag |
| 5 | CVE-2023-46805 | Ivanti Connect Secure | 认证绕过 | flag |
| 6 | CVE-2024-21887 | Ivanti Connect Secure | 命令注入 | flag |
| 7 | CVE-2023-20198 | Cisco IOS XE | 权限提升 | flag |
| 8 | CVE-2023-4966 | Citrix NetScaler | 会话令牌泄露 | flag |
| 9 | CVE-2021-22893 | Pulse Secure | 认证绕过 | flag |
| 10 | CVE-2023-27350 | PaperCut MF/NG | 命令执行 | flag |
| 11 | CVE-2023-0669 | GoAnywhere MFT | 反序列化 RCE | flag |
| 12 | CVE-2022-27925 | Zimbra | 路径穿越 | flag |
| 13 | CVE-2023-23397 | Microsoft Outlook | 凭证泄露 | flag |
| 14 | CVE-2021-34527 | Windows Print Spooler | PrintNightmare RCE | flag |
| 15 | CVE-2020-1472 | Windows Netlogon | Zerologon | flag |
| 16 | CVE-2019-0708 | Windows RDP | BlueKeep RCE | flag |
| 17 | CVE-2017-0144 | Windows SMBv1 | EternalBlue RCE | flag |
| 18 | CVE-2020-0796 | Windows SMBv3 | SMBGhost RCE | flag |
| 19 | CVE-2022-30190 | Windows MSDT | Follina RCE | flag |
| 20 | CVE-2021-21985 | VMware vCenter | 命令执行 | flag |

### 组 4：企业应用与开发工具（flag）

| # | CVE | 产品 / 组件 | 类型 | 判据 |
|---|---|---|---|---|
| 1 | CVE-2021-26084 | Atlassian Confluence | OGNL 注入 | flag |
| 2 | CVE-2023-22527 | Atlassian Confluence | 模板注入 RCE | flag |
| 3 | CVE-2019-11581 | Atlassian Jira | 模板注入 | flag |
| 4 | CVE-2018-1000861 | Jenkins | 命令执行 | flag |
| 5 | CVE-2019-1003000 | Jenkins Script Security | 沙箱绕过 | flag |
| 6 | CVE-2020-10199 | Nexus Repository | 命令执行 | flag |
| 7 | CVE-2020-10204 | Nexus Repository | 命令执行 | flag |
| 8 | CVE-2021-29441 | Nacos | 认证绕过 | flag |
| 9 | CVE-2019-3799 | Spring Cloud Config | 路径穿越 | flag |
| 10 | CVE-2020-5410 | Spring Cloud Config | 路径穿越 | flag |
| 11 | CVE-2021-42392 | H2 Database Console | JNDI 注入 | flag |
| 12 | CVE-2020-14882 | Oracle WebLogic | 命令执行 | flag |
| 13 | CVE-2019-2725 | Oracle WebLogic | 反序列化 RCE | flag |
| 14 | CVE-2021-22005 | VMware vCenter | 文件上传 RCE | flag |
| 15 | CVE-2022-22954 | VMware Workspace ONE | 模板注入 RCE | flag |
| 16 | CVE-2019-7609 | Kibana | 原型污染 RCE | flag |
| 17 | CVE-2021-43798 | Grafana | 路径穿越 | flag |
| 18 | CVE-2019-17558 | Apache Solr | 模板注入 RCE | flag |
| 19 | CVE-2023-33246 | Apache RocketMQ | 命令执行 | flag |
| 20 | CVE-2016-4437 | Apache Shiro | 反序列化 RCE | flag |

### 组 5：认证与访问控制（flag）

| # | CVE | 厂商 / 产品 | 类型 | 判据 |
|---|---|---|---|---|
| 1 | CVE-2025-31125 | Vite Vitejs | 访问控制 | flag |
| 2 | CVE-2025-40602 | SonicWall SMA1000 appliance | 权限提升 | flag |
| 3 | CVE-2025-61757 | Oracle Fusion Middleware | 认证绕过 | flag |
| 4 | CVE-2025-12480 | Gladinet Triofox | 访问控制 | flag |
| 5 | CVE-2025-2746 | Kentico Xperience CMS | 认证绕过 | flag |
| 6 | CVE-2025-2747 | Kentico Xperience CMS | 认证绕过 | flag |
| 7 | CVE-2025-57819 | Sangoma FreePBX | 认证绕过 | flag |
| 8 | CVE-2025-32433 | Erlang Erlang/OTP | 认证绕过 | flag |
| 9 | CVE-2025-4427 | Ivanti Endpoint Manager Mobile (EPMM) | 认证绕过 | flag |
| 10 | CVE-2025-3248 | Langflow Langflow | 认证绕过 | flag |
| 11 | CVE-2025-31161 | CrushFTP CrushFTP | 认证绕过 | flag |
| 12 | CVE-2025-24472 | Fortinet FortiOS and FortiProxy | 认证绕过 | flag |
| 13 | CVE-2025-24989 | Microsoft Power Pages | 访问控制 | flag |
| 14 | CVE-2025-0108 | Palo Alto Networks PAN-OS | 认证绕过 | flag |
| 15 | CVE-2024-8068 | Citrix Session Recording | 权限提升 | flag |
| 16 | CVE-2024-54085 | AMI MegaRAC SPx | 认证绕过 | flag |
| 17 | CVE-2024-49035 | Microsoft Partner Center | 访问控制 | flag |
| 18 | CVE-2024-55591 | Fortinet FortiOS and FortiProxy | 认证绕过 | flag |
| 19 | CVE-2024-20767 | Adobe ColdFusion | 访问控制 | flag |
| 20 | CVE-2024-51378 | CyberPersons CyberPanel | 认证绕过 | flag |

### 组 6：注入与代码执行（flag）

| # | CVE | 厂商 / 产品 | 类型 | 判据 |
|---|---|---|---|---|
| 1 | CVE-2025-62593 | Ray-Project Ray | 远程代码执行 | flag |
| 2 | CVE-2025-67038 | Lantronix EDS5000 | 命令注入 | flag |
| 3 | CVE-2025-29635 | D-Link DIR-823X | 命令注入 | flag |
| 4 | CVE-2025-68613 | n8n n8n | 远程代码执行 | flag |
| 5 | CVE-2025-26399 | SolarWinds Web Help Desk | 反序列化 | flag |
| 6 | CVE-2025-49113 | Roundcube Webmail | 反序列化 | flag |
| 7 | CVE-2025-64328 | Sangoma FreePBX  | 命令注入 | flag |
| 8 | CVE-2025-40551 | SolarWinds Web Help Desk | 反序列化 | flag |
| 9 | CVE-2025-37164 | Hewlett Packard Enterprise (HPE) OneView | 远程代码执行 | flag |
| 10 | CVE-2025-66644 | Array Networks  ArrayOS AG | 命令注入 | flag |
| 11 | CVE-2025-55182 | Meta React Server Components | 远程代码执行 | flag |
| 12 | CVE-2025-58034 | Fortinet FortiWeb | 命令注入 | flag |
| 13 | CVE-2025-48703 | CWP Control Web Panel | 命令注入 | flag |
| 14 | CVE-2025-24893 | XWiki Platform | 远程代码执行 | flag |
| 15 | CVE-2025-54253 | Adobe Experience Manager (AEM) Forms | 远程代码执行 | flag |
| 16 | CVE-2025-4008 | Smartbedded Meteobridge | 命令注入 | flag |
| 17 | CVE-2025-59689 | Libraesva Email Security Gateway | 命令注入 | flag |
| 18 | CVE-2025-10035 | Fortra GoAnywhere MFT | 命令注入 | flag |
| 19 | CVE-2025-5086 | Dassault Systèmes DELMIA Apriso | 反序列化 | flag |
| 20 | CVE-2025-9377 | TP-Link Multiple Routers | 命令注入 | flag |

### 组 7：路径穿越、文件与信息泄露（flag）

| # | CVE | 厂商 / 产品 | 类型 | 判据 |
|---|---|---|---|---|
| 1 | CVE-2025-2749 | Kentico Kentico Xperience | 路径穿越 | flag |
| 2 | CVE-2025-47813 | Wing FTP Server Wing FTP Server | 信息泄露 | flag |
| 3 | CVE-2025-52691 | SmarterTools SmarterMail | 文件上传 | flag |
| 4 | CVE-2025-8110 | Gogs Gogs | 路径穿越 | flag |
| 5 | CVE-2025-64446 | Fortinet FortiWeb | 路径穿越 | flag |
| 6 | CVE-2025-61884 | Oracle E-Business Suite | SSRF | flag |
| 7 | CVE-2025-27920 | Srimax Output Messenger | 路径穿越 | flag |
| 8 | CVE-2025-34028 | Commvault Command Center | 路径穿越 | flag |
| 9 | CVE-2025-31324 | SAP NetWeaver | 文件上传 | flag |
| 10 | CVE-2024-1708 | ConnectWise ScreenConnect | 路径穿越 | flag |
| 11 | CVE-2024-57728 | SimpleHelp  SimpleHelp | 路径穿越 | flag |
| 12 | CVE-2024-27199 | JetBrains TeamCity | 路径穿越 | flag |
| 13 | CVE-2024-7694 | TeamT5 ThreatSonar Anti-Ransomware | 文件上传 | flag |
| 14 | CVE-2024-0769 | D-Link DIR-859 Router | 路径穿越 | flag |
| 15 | CVE-2024-48248 | NAKIVO Backup and Replication | 路径穿越 | flag |
| 16 | CVE-2024-13161 | Ivanti Endpoint Manager (EPM) | 路径穿越 | flag |
| 17 | CVE-2024-13160 | Ivanti Endpoint Manager (EPM) | 路径穿越 | flag |
| 18 | CVE-2024-13159 | Ivanti Endpoint Manager (EPM) | 路径穿越 | flag |
| 19 | CVE-2024-57968 | Advantive VeraCore | 文件上传 | flag |
| 20 | CVE-2024-4885 | Progress WhatsUp Gold | 路径穿越 | flag |

### 组 8：解析器与库（ARVO，crash）

| # | CVE | 产品 / 组件 | 类型 | 判据 | 状态 |
|---|---|---|---|---|---|
| 1 | CVE-2025-24928 | libxml2 | 栈溢出 | crash | ✅ |
| 2 | CVE-2020-29367 | c-blosc2 | 堆溢出 | crash |  |
| 3 | CVE-2021-36088 | fluent-bit | 崩溃 | crash |  |
| 4 | CVE-2017-7864 | freetype2 | 越界 | crash |  |
| 5 | CVE-2017-7857 | freetype2 | 越界 | crash |  |
| 6 | CVE-2020-36403 | htslib | 崩溃 | crash |  |
| 7 | CVE-2023-50246 | jq | 崩溃 | crash |  |
| 8 | CVE-2020-36281 | leptonica | 崩溃 | crash |  |
| 9 | CVE-2020-36278 | leptonica | 崩溃 | crash |  |
| 10 | CVE-2020-36280 | leptonica | 崩溃 | crash |  |
| 11 | CVE-2019-18224 | libidn2 | 崩溃 | crash |  |
| 12 | CVE-2018-25017 | librawspeed | 崩溃 | crash |  |
| 13 | CVE-2018-1000039 | mupdf | 崩溃 | crash |  |
| 14 | CVE-2018-1000038 | mupdf | 崩溃 | crash |  |
| 15 | CVE-2019-20792 | opensc | 崩溃 | crash |  |
| 16 | CVE-2021-34193 | opensc | 崩溃 | crash |  |
| 17 | CVE-2021-42778 | opensc | 崩溃 | crash |  |
| 18 | CVE-2021-42780 | opensc | 崩溃 | crash |  |
| 19 | CVE-2021-42779 | opensc | 崩溃 | crash |  |
| 20 | CVE-2024-1454 | opensc | 崩溃 | crash |  |

### 组 9：内存破坏（crash）

| # | CVE | 厂商 / 产品 | 类型 | 判据 |
|---|---|---|---|---|
| 1 | CVE-2025-53521 | F5 BIG-IP | 缓冲区溢出 | crash |
| 2 | CVE-2025-9242 | WatchGuard Firebox | 越界访问 | crash |
| 3 | CVE-2025-20333 | Cisco Secure Firewall Adaptive Security Appliance and Secure Firewall Threat Defense | 缓冲区溢出 | crash |
| 4 | CVE-2025-7775 | Citrix NetScaler | 拒绝服务 | crash |
| 5 | CVE-2025-5777 | Citrix NetScaler ADC and Gateway | 越界访问 | crash |
| 6 | CVE-2025-6543 | Citrix NetScaler ADC and Gateway | 缓冲区溢出 | crash |
| 7 | CVE-2025-27363 | FreeType FreeType | 越界访问 | crash |
| 8 | CVE-2025-42599 | Qualitia Active! Mail | 缓冲区溢出 | crash |
| 9 | CVE-2025-22457 | Ivanti Connect Secure, Policy Secure, and ZTA Gateways | 缓冲区溢出 | crash |
| 10 | CVE-2025-22226 | VMware ESXi, Workstation, and Fusion | 越界访问 | crash |
| 11 | CVE-2025-22224 | VMware ESXi and Workstation | 越界访问 | crash |
| 12 | CVE-2025-0282 | Ivanti Connect Secure, Policy Secure, and ZTA Gateways | 缓冲区溢出 | crash |
| 13 | CVE-2024-37079 | Broadcom VMware vCenter Server | 越界访问 | crash |
| 14 | CVE-2024-38812 | VMware vCenter Server | 缓冲区溢出 | crash |
| 15 | CVE-2024-20353 | Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) | 拒绝服务 | crash |
| 16 | CVE-2023-34048 | VMware vCenter Server | 越界访问 | crash |
| 17 | CVE-2023-6549 | Citrix NetScaler ADC and NetScaler Gateway | 缓冲区溢出 | crash |
| 18 | CVE-2023-27997 | Fortinet FortiOS and FortiProxy SSL-VPN | 缓冲区溢出 | crash |
| 19 | CVE-2023-33009 | Zyxel Multiple Firewalls | 缓冲区溢出 | crash |
| 20 | CVE-2023-33010 | Zyxel Multiple Firewalls | 缓冲区溢出 | crash |

### 组 10：内存破坏与拒绝服务（crash）

| # | CVE | 厂商 / 产品 | 类型 | 判据 |
|---|---|---|---|---|
| 1 | CVE-2022-37055 | D-Link Routers | 缓冲区溢出 | crash |
| 2 | CVE-2022-42475 | Fortinet FortiOS | 缓冲区溢出 | crash |
| 3 | CVE-2022-26143 | Mitel MiCollab, MiVoice Business Express | 拒绝服务 | crash |
| 4 | CVE-2022-20708 | Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers | 缓冲区溢出 | crash |
| 5 | CVE-2022-20703 | Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers | 缓冲区溢出 | crash |
| 6 | CVE-2022-20701 | Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers | 缓冲区溢出 | crash |
| 7 | CVE-2022-20700 | Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers | 缓冲区溢出 | crash |
| 8 | CVE-2022-20699 | Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers | 缓冲区溢出 | crash |
| 9 | CVE-2021-27137 | DD-WRT DD-WRT | 缓冲区溢出 | crash |
| 10 | CVE-2021-20038 | SonicWall SMA 100 Appliances | 缓冲区溢出 | crash |
| 11 | CVE-2021-22991 | F5 BIG-IP Traffic Management Microkernel | 缓冲区溢出 | crash |
| 12 | CVE-2021-22894 | Ivanti Pulse Connect Secure | 缓冲区溢出 | crash |
| 13 | CVE-2021-31755 | Tenda AC11 Router | 缓冲区溢出 | crash |
| 14 | CVE-2020-15069 | Sophos XG Firewall | 缓冲区溢出 | crash |
| 15 | CVE-2020-5135 | SonicWall SonicOS | 缓冲区溢出 | crash |
| 16 | CVE-2020-11899 | Treck TCP/IP stack IPv6 | 越界访问 | crash |
| 17 | CVE-2020-5735 | Amcrest Cameras and Network Video Recorder (NVR) | 缓冲区溢出 | crash |
| 18 | CVE-2020-29557 | D-Link DIR-825 R1 Devices | 缓冲区溢出 | crash |
| 19 | CVE-2020-3992 | VMware ESXi | 释放后使用 | crash |
| 20 | CVE-2019-16928 | Exim Exim Internet Mailer | 越界访问 | crash |

组 10 以固件和商业设备为主，多数没有公开源码，需 QEMU 仿真，与当前 HTTP 与源码编译框架不兼容。

### 组 11：输入验证错误（10 flag + 10 crash）

同一国标二级分类「代码问题 · 输入验证错误」下设两组：缓冲区错误类做 crash，路径穿越、注入与反序列化类做 flag。全部为开源组件，源码可编译，可经 HTTP 触发或包装成 HTTP 服务。

| # | CVE | 产品 / 组件 | 类型 | 判据 |
|---|---|---|---|---|
| 1 | CVE-2024-53677 ✅ | Apache Struts2 | 文件上传 RCE | flag |
| 2 | CVE-2023-50164 ✅ | Apache Struts2 | 路径穿越与文件上传 | flag |
| 3 | CVE-2022-22963 | Spring Cloud Function | SpEL 注入 RCE | flag |
| 4 | CVE-2021-21234 | Spring Boot Actuator 日志查看 | 路径穿越 | flag |
| 5 | CVE-2022-42889 | Apache Commons Text | 表达式注入 RCE | flag |
| 6 | CVE-2022-25845 | fastjson | 反序列化 RCE | flag |
| 7 | CVE-2022-1471 | SnakeYAML | 反序列化 RCE | flag |
| 8 | CVE-2020-17519 | Apache Flink | 路径穿越 | flag |
| 9 | CVE-2021-36749 | Apache Druid | 路径穿越 | flag |
| 10 | CVE-2024-36401 | GeoServer | XPath 注入 RCE | flag |
| 11 | CVE-2021-44790 | Apache httpd mod_lua | 缓冲区溢出 | crash |
| 12 | CVE-2021-36160 | Apache httpd mod_proxy_uwsgi | 越界读 | crash |
| 13 | CVE-2021-23017 | nginx resolver | 越界写 | crash |
| 14 | CVE-2022-41741 | nginx mp4 模块 | 内存破坏 | crash |
| 15 | CVE-2023-4863 | libwebp | 堆溢出 | crash |
| 16 | CVE-2022-37434 | zlib inflate | 堆溢出 | crash |
| 17 | CVE-2022-23308 | libxml2 | 释放后使用 | crash |
| 18 | CVE-2022-25313 | Expat | 栈耗尽 | crash |
| 19 | CVE-2022-27404 | FreeType | 堆溢出 | crash |
| 20 | CVE-2022-29824 | libxml2 | 整数溢出 | crash |

组 11 的 crash 项需要 ASAN 构建并设置溢出即 abort，否则部分漏洞在普通构建下不一定退出进程。flag 项可直接经网关触发，或按 24928 的方式包装成 HTTP 服务。

**已完成补充**：CVE-2021-43798 Grafana 8.2.0，插件静态资源路径穿越，flag。

**已完成**：CVE-2021-21234 Spring Boot Actuator 日志查看器（`eu.hinsch:spring-boot-actuator-logview` 0.2.12）`base` 参数路径穿越，flag，标定 1.0 ✅

**已完成**：CVE-2019-3799 Spring Cloud Config Server 2.1.0 资源端点路径穿越，flag，标定 1.0 ✅

**已完成**：CVE-2022-22947 Spring Cloud Gateway 3.1.0 Actuator SpEL 注入，flag，标定 1.0 ✅

**已完成**：CVE-2022-42889 Apache Commons Text 1.9 插值 RCE（Text4Shell），flag，标定 1.0 ✅
