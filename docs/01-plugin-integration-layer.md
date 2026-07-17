# 插件接入层：`icsnpp-mms` 如何挂到 Zeek 上

理解 `icsnpp-mms` 可以先不看 MMS 协议细节，也不急着钻进 `asn1c/`。第一层逻辑是：**它如何作为 Zeek 插件被加载，并注册成协议分析器**。

> Zeek 是怎么认识 `icsnpp-mms`，并把 MMS 数据交给它处理的？

## 1. 项目定位

`icsnpp-mms` 是面向 Zeek 的 MMS 协议分析插件，在工业控制场景常见，与 IEC 61850 关系密切。

整体职责：

```text
接入 Zeek  →  解析 MMS PDU  →  生成 Zeek 事件和日志
```

本篇只关注第一步。接入层核心文件：

```text
plugin/src/Plugin.cc   注册插件和 analyzer
plugin/src/Analyzer.cc 接收协议数据（解析逻辑在第二篇）
```

## 2. 插件入口：`Plugin::Configure`

`plugin/src/Plugin.cc` 的核心函数：

```cpp
zeek::plugin::Configuration Plugin::Configure()
```

做两件事：声明插件元信息，注册 MMS analyzer。

**元信息**——Zeek 加载时识别插件身份：

```cpp
config.name = "OSS::MMS";
config.version.major = VERSION_MAJOR;  // 版本号来自 VERSION 文件
config.version.minor = VERSION_MINOR;
config.version.patch = VERSION_PATCH;
```

**注册 analyzer**——告诉 Zeek 遇到 MMS 时创建哪个分析器：

```cpp
static const std::string simple_name = "MMS";
static const std::string iso_name = util::canonify_name("ISO:1.0.9506.2.1");

AddComponent(new zeek::analyzer::Component(
    simple_name,
    [](zeek::Connection *c) -> zeek::analyzer::Analyzer* {
        return new Analyzer(simple_name.c_str(), c);
    }
));

AddComponent(new zeek::analyzer::Component(
    iso_name,
    [](zeek::Connection *c) -> zeek::analyzer::Analyzer* {
        return new Analyzer(iso_name.c_str(), c);
    }
));
```

`AddComponent` 注册的是工厂函数：上游协议层需要 MMS analyzer 时，Zeek 调用 lambda，为这条连接 `new Analyzer(...)`。

## 3. 为什么注册两个名称？

两个名字指向同一个 `Analyzer` 实现：

```text
MMS                  直观协议名
ISO:1.0.9506.2.1     MMS 在 ISO/OSI 应用层的标识
```

MMS 不直接跑在 TCP 上，通常经多层 ISO/OSI 封装：

```text
TCP → TPKT → COTP → Session → Presentation → ACSE → MMS
```

上游层（TPKT、COTP、SESS、PRES、ACSE 等插件）识别出 MMS 时，可能报 ISO 标识 `1.0.9506.2.1` 而非字符串 `MMS`。两个名字都注册，协议栈无论用哪种标识都能找到 analyzer 并递交数据。

## 4. 数据如何进入 analyzer

`Analyzer` 定义在 `plugin/src/Analyzer.h` 和 `Analyzer.cc`，继承 Zeek analyzer 基类。构造函数只做基类初始化，没有额外逻辑：

```cpp
Analyzer::Analyzer(const char* name, zeek::Connection* c)
    : zeek::analyzer::Analyzer(name, c) {}
```

接入层主线：

```text
Zeek 启动 → 加载插件 → Plugin::Configure()
  → 注册 MMS analyzer
  → 上游识别到 MMS 数据
  → 创建 mms::Analyzer 实例
  → 数据进入 Analyzer::DeliverPacket（第二篇）
```

`Plugin.cc` 不解析 MMS，只负责把 analyzer 挂到 Zeek 插件体系里。

## 5. 构建与安装

根目录构建相关文件：

```text
configure / CMakeLists.txt / plugin.cmake   编译规则
VERSION                                      版本号（供 Plugin.cc 使用）
zkg.meta                                     zkg 包管理元信息
```

本地编译：`./configure && make && make install`

通过 zkg 安装：`zkg install https://github.com/DINA-community/icsnpp-mms`

本项目既是 **Zeek plugin**（含 C++ analyzer，编译为动态库），也是 **Zeek package**（可通过 zkg 管理）。

## 6. 小结

接入层的核心问题：

```text
如何让 Zeek 认识这个插件
如何注册为 MMS analyzer
如何让上游协议层把数据递交给它
```

关键文件：`Plugin.cc`、`Analyzer.cc`，以及 `configure` / `CMakeLists.txt` / `zkg.meta`。

下一篇进入 `Analyzer::DeliverPacket`，看 MMS PDU 如何从二进制变成 Zeek 结构化数据。
