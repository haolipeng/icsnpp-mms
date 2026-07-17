# 协议解析层：MMS PDU 如何变成 Zeek 能理解的数据

第一篇说明了 `Plugin.cc` 如何注册 analyzer，以及 Zeek 如何创建 `mms::Analyzer` 实例。数据能进入 analyzer 之后，第二层逻辑是：**如何把 MMS 二进制 PDU 解析成 Zeek 脚本层能处理的事件**。

这一篇先解决一个问题：

> Analyzer 收到 MMS 数据后，如何把二进制 PDU 解析成 Zeek 类型？

## 1. 承接第一篇：数据已经进入 Analyzer

从整体职责看，`icsnpp-mms` 做三件事：

```text
接入 Zeek
  → 解析 MMS PDU
  → 生成 Zeek 事件和日志
```

第一篇只关注第一步；第二篇关注中间这一步：**解析 MMS PDU**。

在当前项目中，二者的分工是：

```text
Plugin.cc  负责注册 analyzer
Analyzer.cc  负责处理进入 analyzer 的 MMS 数据
```

也可以把二者的关系理解成：

```text
Plugin.cc
  负责“注册我是谁，我能处理什么协议”

Analyzer.cc
  负责“收到协议数据后怎么处理”
```

第二篇从 `Analyzer::DeliverPacket` 开始，关注 MMS 数据进入 analyzer 之后发生了什么。

## 2. `Analyzer::DeliverPacket` 是解析入口

关键文件：

```text
plugin/src/Analyzer.cc
plugin/src/Analyzer.h
```

这个文件的核心函数是：

```cpp
void Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t, const IP_Hdr*, int)
```

Zeek 每收到一段属于 MMS 协议的数据，就会调用这个函数。代码注释里说明了几个关键参数：

```text
data  指向本次 MMS 数据的指针
len   本次 MMS 数据的长度
orig  数据方向：true 表示来自连接发起方（client/originator），false 表示来自响应方
```

`seq`、`ip`、`caplen` 是 Zeek 传入的额外参数，当前实现中没有使用。

简单说，这个函数告诉后续代码：

> 这里有一段长度为 `len` 的 MMS 二进制数据，方向是 `orig`，请把它解析出来。

## 3. 数据形态如何变化

在进入具体步骤之前，可以先建立一张整体地图。`DeliverPacket` 做的事情，本质上是让数据经历三次形态变化：

```text
原始 MMS 数据（二进制）
  → BER 解码
  → asn1c C 结构
  → 约束检查
  → Zeek Val
  → mms_pdu 事件
```

对应到代码里的变量，大致是：

```text
data / len          Zeek 交进来的原始字节
pdu_raw             ber_decode 解码后的 C 结构
pdu                 process_MMSpdu 转换后的 Zeek 值
```

这条主线可以记成：

```text
DeliverPacket
  → ber_decode
  → asn_check_constraints
  → process_MMSpdu
  → enqueue_mms_pdu
```

## 4. 第一步：用 `ber_decode` 解码 MMS

`DeliverPacket` 拿到数据后，首先借助 asn1c 做 BER 解码。核心代码是：

```cpp
MMSpdu *pdu_raw = NULL;
auto desc = &asn_DEF_MMSpdu;

asn_dec_rval_t rval = ber_decode(nullptr, desc, reinterpret_cast<void**>(&pdu_raw), data, len);
if (rval.code != RC_OK) {
    Weird("mms_parse_error", "unable to parse packet");
    return;
}
```

这里几个名字需要认识：

```text
MMSpdu
  MMS 顶层 PDU 类型

asn_DEF_MMSpdu
  asn1c 为 MMSpdu 生成的类型描述符

ber_decode
  根据 ASN.1 类型描述符，把 BER 编码的二进制数据解码成 C 结构
```

`pdu_raw` 初始为 `NULL`，解码成功后由 asn1c 填充为 C 结构。此时数据形态已经从「一串二进制」变成了「有字段、有层次的结构体」。

如果 BER 解码失败，说明当前数据无法被识别为合法的 MMS PDU，函数会记录 `mms_parse_error` 并直接返回，不再往下走。

## 5. 第二步：ASN.1 约束检查

解码成功后，还有一步约束检查：

```cpp
char errbuf[128];
size_t errlen = sizeof(errbuf)/sizeof(errbuf[0]);
if (asn_check_constraints(desc, pdu_raw, errbuf, &errlen)) {
    Weird("mms_constraint_error", errbuf);
    return;
}
```

`asn_check_constraints` 检查解码后的 C 结构是否符合 ASN.1 类型约束。

这里有一个容易混淆的点：

```text
它不是 MMS 业务逻辑校验
它主要检查 ASN.1 层面的结构合法性
```

也就是说，这一步关心的是「这个 PDU 结构本身是否合法」，而不是「这是不是一次合法的 Read 或 Write 请求」。

检查失败时，会记录 `mms_constraint_error` 并返回。

## 6. `plugin/src/asn1c/` 目录的作用

BER 解码依赖的 C 结构，来自 `plugin/src/asn1c/` 目录。这是 asn1c 根据 MMS ASN.1 定义自动生成的 C 代码。

重点文件包括：

```text
plugin/src/asn1c/MMSpdu.h
plugin/src/asn1c/MMSpdu.c
plugin/src/asn1c/Confirmed-RequestPDU.h
plugin/src/asn1c/ConfirmedServiceRequest.h
plugin/src/asn1c/Read-Request.h
plugin/src/asn1c/Write-Request.h
```

阅读 asn1c 生成代码时，几个概念会反复出现：

```text
CHOICE     ASN.1 中的多选一结构
SEQUENCE   ASN.1 中的结构体式字段组合
OPTIONAL   ASN.1 中的可选字段
present    表示当前 CHOICE 选择了哪个分支
choice     保存 CHOICE 实际内容的字段
```

不需要逐行阅读整个 `asn1c/` 目录。更实用的读法是：

```text
优先理解 MMSpdu 这个顶层结构
再根据 Read / Write / Identify 等具体服务按需查看对应文件
```

## 7. 第三步：`process_MMSpdu` 转成 Zeek 类型

C 结构是 asn1c 的世界，Zeek 脚本层读不懂它。转换工作由 `process_MMSpdu` 完成：

```cpp
auto pdu = process_MMSpdu(pdu_raw);
```

关键文件：

```text
plugin/src/process.cc
plugin/src/process.h
```

`process_MMSpdu` 的作用，是把 asn1c 的 `MMSpdu` C 结构转换成 Zeek 的 `Val`。涉及的 Zeek C++ 类型包括：

```text
RecordVal   Zeek record 值
VectorVal   Zeek vector 值
StringVal   Zeek string 值
IntVal      Zeek int 值
IntrusivePtr<Val>   Zeek C++ 层常用的引用计数智能指针
```

需要强调：

```text
process.cc 是生成代码
阅读时应该先看 process_MMSpdu 的入口和转换模式
不建议一开始逐行读完整文件
```

## 8. `types.zeek` 与 `process.cc` 的对应关系

Zeek 脚本层看到的数据类型，定义在 `plugin/scripts/types.zeek`：

```text
types.zeek  定义 Zeek 脚本层可见的数据类型
process.cc  根据这些类型创建对应的 Zeek Val
```

二者的对应关系是：

```text
Zeek record   ↔ C++ RecordVal
Zeek vector   ↔ C++ VectorVal
Zeek enum     ↔ C++ EnumVal
Zeek string   ↔ C++ StringVal
Zeek int      ↔ C++ IntVal
```

如果 `process.cc` 中 `AssignField` 的字段名，和 `types.zeek` 中 record 的字段名不一致，C++ 转换层和 Zeek 脚本层就无法正确衔接。

## 9. 第四步：触发 `mms_pdu` 事件

转换完成后，最后一步是把解析结果投递到 Zeek 脚本层：

```cpp
zeek::BifEvent::mms::enqueue_mms_pdu(this, Conn(), orig, pdu);
```

这里：

```text
enqueue_mms_pdu   把 C++ 层解析出的 Zeek Val 投递为 Zeek 事件
orig              数据方向
pdu               process_MMSpdu 转换出来的 Zeek 值
```

事件声明在 `plugin/src/events.bif`：

```zeek
event mms_pdu%(c: connection, is_orig: bool, apdu: MMSpdu%);
```

本节只说明 C++ 到 Zeek 脚本层的交接。至于 `mms_pdu` 如何被拆成 `readRequest`、`writeResponse`、`IdentifyResponse` 等业务事件，放到第三篇展开。

## 10. 第二层代码主线

到这里，可以把协议解析层的代码主线总结为：

```text
上游协议层把 MMS 数据交给 Analyzer
  → DeliverPacket(data, len, orig)
  → ber_decode 解码成 pdu_raw
  → asn_check_constraints 检查结构合法性
  → process_MMSpdu 转成 Zeek Val
  → enqueue_mms_pdu 抛出 mms_pdu 事件
```

对应到代码文件：

```text
plugin/src/Analyzer.cc
  → 解析入口，串联整条流程

plugin/src/asn1c/
  → BER 解码后的 C 结构定义

plugin/src/process.cc
  → C 结构 → Zeek Val

plugin/scripts/types.zeek
  → 脚本层类型定义

plugin/src/events.bif
  → mms_pdu 事件声明
```

C++ 解析层的职责可以概括成：

```text
接收 MMS 字节数据
解码 ASN.1 BER
检查结构合法性
转换为 Zeek 类型
抛出 mms_pdu 事件
```

## 11. 阅读这一层需要补充什么知识？

如果只理解协议解析层，暂时不需要深入 Read、Write 等业务事件。更需要补的是下面几个概念：

```text
ASN.1 和 BER 编码是什么
asn1c 生成代码的基本结构
Zeek Val / RecordVal 是什么
BIF 事件如何从 C++ 投递到 Zeek 脚本层
types.zeek 与 C++ 转换层的对应关系
```

## 12. 小结

`icsnpp-mms` 的第二层逻辑是协议解析。

这一层的核心不是“如何写日志”，而是：

```text
如何把 MMS 二进制数据解码成结构化对象
如何把它转换成 Zeek 能理解的类型
如何抛出 mms_pdu 事件交给脚本层
```

关键文件是：

```text
plugin/src/Analyzer.cc
plugin/src/asn1c/
plugin/src/process.cc
plugin/scripts/types.zeek
plugin/src/events.bif
```

理解完这一层之后，下一篇就可以继续看 Zeek 脚本层如何从 `mms_pdu` 拆出具体业务事件，并最终生成日志。
