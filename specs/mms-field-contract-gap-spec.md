# 规格：MMS 行为日志字段契约补齐

标签：`ready-for-agent`

## 问题陈述

当前 MMS 插件已经能够解析部分 MMS 会话、名称列表、变量读写、变量属性和变量列表属性，并输出多类 Zeek 日志。但这些日志仍沿用原始插件字段口径：连接地址集中在 Zeek `conn_id` 结构中，变量和对象字段分散在不同日志内，成功失败使用布尔值和原始诊断值表达，方向、invoke ID、解析状态、高风险操作标识、文件服务路径和部分错误场景没有稳定落盘。

行为分析系统需要消费统一的 MMS 行为日志字段契约。如果字段缺失或语义不一致，下游关联、基线判断、告警解释和回归验证都需要为每类日志写特例，且无法区分“解析失败”“请求响应未匹配”“协议本身无字段”和“上游模块尚未补齐”的状态。

## 解决方案

fork 后保留现有多日志模型，但为每类 MMS 业务日志补齐统一字段口径。所有业务日志都应使用统一的连接端点字段、操作字段、对象字段、结果字段、错误字段、风险字段和解析状态字段；在能从协议 PDU 直接获得上下文时落盘，在只能由其他模块补齐时预留字段或接口，并以明确的状态标识字段不可得原因。

实现时应把现有 `is_orig` 和 `invokeID` 从通用 PDU 分发链路继续传递到业务事件和日志层，扩展 Confirmed Request、Confirmed Response、Confirmed Error、Reject、Cancel Error、Conclude Error、DataAccessError 和文件服务的可观测覆盖。文件服务采用保守提取策略：直接可见文件名时填充文件路径；需要句柄关联的 FileRead/FileClose 通过文件句柄状态回填，关联失败时保留日志并标记为部分结果。

解析异常不应只散落在 weird 输出中。MMS 业务日志需要可观测的 `parse_status` 和 `parse_error`，用于表达成功、部分成功、解析失败、请求响应未匹配和不适用等状态。

## 用户故事

1. 作为行为分析系统，我希望每条 MMS 业务日志都包含 `ts` 和 `uid`，从而能把 MMS 行为与 Zeek 连接和时间序列数据关联起来。
2. 作为行为分析系统，我希望 MMS 端点字段统一输出为 `src_ip`、`dst_ip`、`src_port` 和 `dst_port`，从而不需要理解 Zeek 原生 `conn_id` 的内部结构。
3. 作为行为分析系统，我希望 MAC 地址由后续二层观测或通信关系富化模块补齐，而不是由 MMS 协议解析日志预留，从而避免把富化事实误认为协议解析事实。
4. 作为行为分析系统，我希望 MAC 地址缺失被表达为部分数据，而不是解析失败，从而避免下游把富化缺口误判为 MMS 解析缺口。
5. 作为安全分析员，我希望每条 MMS 业务事件都包含 `direction`，从而能判断该操作来自客户端还是服务端。
6. 作为安全分析员，我希望 `direction` 由 MMS `is_orig` 和 Zeek connection 语义统一推导，从而所有 MMS 日志使用一致的方向含义。
7. 作为检测规则作者，我希望 `operation` 使用统一枚举，从而能一致匹配 read、write、report、name list、属性查询、文件、控制和错误操作。
8. 作为检测规则作者，我希望操作名的大小写和语义保持一致，从而规则不需要适配插件内部的不同命名。
9. 作为事件关联模块，我希望 Confirmed Request 和 Confirmed Response 日志包含 `invoke_id`，从而能在解析器外部观察请求/响应配对。
10. 作为事件关联模块，我希望 Confirmed Error 日志包含 `invoke_id`，从而能把失败操作关联回原始请求。
11. 作为事件关联模块，我希望 Unconfirmed PDU 日志中的 `invoke_id` 留空，从而清楚表达协议层面本来没有该字段。
12. 作为行为分析系统，我希望对象名统一规范化为 `object_path`，从而变量、名称列表和属性日志都暴露同一种对象标识。
13. 作为行为分析系统，我希望在必要时保留原始对象上下文，从而规范化过程中不丢失 domain、list 等信息。
14. 作为 IEC 61850 分析员，我希望从 `object_path` 尽力拆分 `ld`、`ln`、`do` 和 `da`，从而按常见 IEC 61850 命名组件聚合 MMS 对象。
15. 作为 IEC 61850 分析员，我希望 `ld`/`ln`/`do`/`da` 拆分失败时只留空这些组件字段，不降低整条事件状态，从而厂商自定义对象路径仍可使用。
16. 作为文件行为检测模块，我希望 FileOpen 操作在文件名直接可见时产出包含文件路径的业务日志，从而文件下载和上传变得可观测。
17. 作为文件行为检测模块，我希望 FileRead 操作复用 FileOpen 建立的文件句柄上下文，从而把读文件行为关联回文件路径。
18. 作为文件行为检测模块，我希望 FileClose 操作复用并释放文件句柄上下文，从而能界定文件传输会话边界。
19. 作为文件行为检测模块，我希望 FileDelete 操作记录直接可见的文件路径，从而识别破坏性文件行为。
20. 作为文件行为检测模块，我希望 FileDirectory 操作记录查询路径或目录名，从而观察目录浏览行为。
21. 作为文件行为检测模块，我希望 ObtainFile 操作在存在上下文时记录源路径和目标路径，从而观察服务端文件传输请求。
22. 作为文件行为检测模块，我希望文件句柄关联失败时仍产出部分日志，而不是丢弃事件，从而不完整流量也能留下证据。
23. 作为下游数据模型，我希望把布尔 `success` 规范化为 `result`，从而用 `success`、`failure`、`unknown` 或 `not_applicable` 表达结果。
24. 作为下游数据模型，我希望保留现有 `diag` 原始值，从而不丢失详细解析诊断信息。
25. 作为下游数据模型，我希望新增统一 `error_code`，从而一致比较服务错误、数据访问错误、拒绝错误、取消错误和结束错误。
26. 作为下游数据模型，我希望成功事件使用 `error_code=none`，从而成功行不需要特殊空值处理。
27. 作为下游数据模型，我希望无法映射的失败使用 `error_code=unknown_error`，从而错误映射缺口保持可见。
28. 作为检测规则作者，我希望 `is_high_risk_operation` 由规范化操作的静态集合计算，从而轻松过滤高风险写入、控制、文件变更和破坏性动作。
29. 作为通信关系模块，我希望预留或可富化 `src_ip_seen`、`src_mac_seen`、`mms_ip_pair_seen` 和 `mms_full_pair_seen` 字段，从而在不改变 MMS 解析语义的情况下附加基线事实。
30. 作为通信关系模块，我希望这些基线事实字段由独立富化层负责，而不是由 MMS 会话摘要日志或解析层直接判断，从而保持协议日志与关系判断的职责分离。
31. 作为解析质量监控模块，我希望业务日志包含 `parse_status`，从而统计完整解析、部分解析、解析失败、未匹配和不适用等场景。
32. 作为解析质量监控模块，我希望业务日志包含 `parse_error`，从而把已知 ISO 栈和 MMS parse weird 与受影响行为放在同一上下文中。
33. 作为测试维护者，我希望已经到达 MMS PDU 分发但没有产出业务日志的样本成为回归用例，从而不遗漏 request-only、错误和未覆盖服务路径。
34. 作为测试维护者，我希望只到达 ISO 栈日志的样本被单独分类，从而不把解析器覆盖缺口与会话建立不完整混在一起。
35. 作为插件维护者，我希望现有多日志输出仍可识别，从而当前消费者可以渐进迁移。
36. 作为插件维护者，我希望提供共享字段规范化 helper，从而每类 MMS 业务日志都用同一套端点、结果、错误、对象、风险和解析状态规则。
37. 作为插件维护者，我希望请求缓存携带足够上下文，覆盖变量、名称列表、属性、文件和错误响应，从而能在最高可用业务层级产生日志。
38. 作为插件维护者，我希望 stale invoke 和文件句柄缓存随连接生命周期清理，从而长时间流量不会积累无效状态。
39. 作为安全分析员，我希望 ConfirmedError、Reject、CancelError、ConcludeError 和 DataAccessError 都产出可观测字段，从而在同一调查流程中查看成功操作和失败协议结果。
40. 作为项目维护者，我希望实现不依赖 SCD/CID/ICD、资产清单、信号点表或人工语义映射，从而 V1 保持仅基于流量且可复现。

## 实现决策

- 保留现有多日志模型。该工作扩展当前 MMS 会话摘要日志、名称列表、变量访问、变量列表访问、变量属性和变量列表属性输出，而不是替换为单一扁平日志。
- 为所有业务日志使用共享 MMS 业务字段契约。每类日志都应暴露适用于自身领域的通用字段，对协议不适用的值留空或标记为 `not_applicable`。
- 将 Zeek 连接端点适配为项目端点字段。`src_ip`、`dst_ip`、`src_port` 和 `dst_port` 从连接发起方/响应方元组派生，并保持一致规范。
- `src_mac`、`dst_mac`、`src_ip_seen`、`src_mac_seen`、`mms_ip_pair_seen` 和 `mms_full_pair_seen` 不纳入 MMS 会话摘要日志 V1，留给独立通信关系/基线富化层负责。
- 从 MMS PDU 分发点保留并传播方向。方向必须传递到服务级、变量级、配对级、文件服务和错误处理链路。
- 从 Confirmed PDU 保留并传播 `invoke_id`。任何由 Confirmed Request、Confirmed Response 或 Confirmed Error 生成的业务日志都应包含 invoke ID；Unconfirmed 服务按协议语义留空。
- 将操作规范化为统一枚举。V1 至少覆盖 identify/initiate、read、write、report、get_name_list、get_variable_access_attributes、get_named_variable_list_attributes、file_open、file_read、file_close、file_delete、file_directory、obtain_file、confirmed_error、reject、cancel_error、conclude_error，以及能产出业务日志的 parse_error 相关分类。
- 将对象名规范化为 `object_path`。变量名、变量列表名、名称列表的 domain/value 上下文和属性查询名都应进入同一种对象路径表达，同时在确有价值时保留日志特有上下文。
- 增加 IEC 61850 对象组件的尽力拆分。`ld`、`ln`、`do` 和 `da` 只从可见的 `object_path` 派生；拆分失败时组件字段留空，不把事件标记为失败。
- 增加文件服务可观测性。FileOpen、FileRead、FileClose、FileDelete、FileDirectory 和 ObtainFile 应产出文件服务业务日志，或扩展某个合适的现有业务日志族并加入文件相关字段。
- 按连接跟踪文件句柄。FileRead 和 FileClose 可以使用文件句柄或文件状态机标识回填 FileOpen 中观察到的路径；关联缺失时仍产出事件，并设置 `parse_status=partial` 和明确的未匹配原因。
- 将现有成功和诊断字段规范化为结果字段。`result` 替代仅布尔的结果语义，支持 `success`、`failure`、`unknown` 和 `not_applicable`。
- 保留原始诊断并新增统一错误码。现有诊断值继续可见，`error_code` 提供跨服务稳定值。成功事件使用 `none`，未映射失败使用 `unknown_error`。
- 从静态操作集合计算高风险操作标识。V1 风险分类是确定性的，不依赖外部资产或信号点语义。
- 将 parse weird 映射到业务可见解析字段。ISO 栈和 MMS 解析失败应在影响业务日志或解释部分结果时体现为 `parse_status` 和 `parse_error`。
- 显式分类请求/响应不匹配。缓存请求缺失、响应上下文缺失和文件句柄缺失不应在已有足够协议上下文时静默丢弃日志，而应产出部分事件。
- 将生成的 ASN.1 类型视为解析输入，而不是公共字段契约。字段契约应由 Zeek 脚本层业务 record 和 helper 承担；C++ 改动只负责传递脚本层无法自行推断的协议事实。

## 测试决策

- 最高测试边界是回放 MMS PCAP 样本后的 Zeek 日志输出。测试应断言外部行为：日志文件是否生成、字段是否存在、字段名是否正确、规范化枚举值是否符合契约、请求/响应关联是否正确、解析状态是否符合预期。
- 次级测试边界是 MMS PDU 到服务级事件的分发。样本已经到达 MMS 但没有业务日志时，用该边界区分“解析器已收到 PDU”和“业务 handler 覆盖不足”。
- 现有 parser 和 plugin 可见性测试继续作为冒烟覆盖。新增测试应围绕业务日志行为编写 btest，而不是断言内部 helper 实现细节。
- 字段契约测试应覆盖每个现有业务日志族和新增文件服务覆盖。每个被覆盖日志都应断言 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`direction`、`operation`、适用时的 `invoke_id`、适用时的 `object_path` 或 `file_path`、`result`、`error_code`、`is_high_risk_operation`、`parse_status` 和 `parse_error`。
- 方向测试应包含 originator 和 responder PDU，并验证请求、响应、上报和错误事件都保留预期方向。
- invoke ID 测试应覆盖成功的读/写/名称列表/属性响应、confirmed error、request-only 抓包和 unconfirmed report。
- 对象路径测试应覆盖 domain-specific、VMD-specific、AA-specific、变量列表和名称列表上下文。
- IEC 61850 拆分测试应包含一个可拆分对象路径和一个不可拆分的厂商自定义对象路径。后者应保持为有效事件，只是组件字段为空。
- 结果和错误映射测试应覆盖成功、DataAccessError、ConfirmedError 服务错误、reject/cancel/conclude 错误、未知映射兜底和不适用结果。
- 文件服务测试应覆盖直接文件名提取、基于句柄的 FileRead/FileClose 路径回填、句柄关联失败、FileDelete、FileDirectory 和 ObtainFile 路径上下文。
- 解析状态测试应覆盖正常成功、文件句柄关联导致的部分结果、请求/响应未匹配、MMS 解析错误、presentation 解析错误，以及只到达下层 ISO 栈日志的样本。
- 回归样本应包含当前只产出 `mms.log` 但没有读/写/名称列表/文件业务日志的流量、能成功产出变量写日志的流量、能成功产出名称列表日志的流量，以及因为 ISO 会话不完整而没有进入 MMS analyzer 的流量。
- 好的测试不应绑定 helper 函数名、缓存表名或生成 ASN.1 转换内部细节，而应断言日志消费者能观察到的行为。

## 不在范围

- 不从 SCD、CID、ICD、资产清单、信号点表或人工点表映射推断业务语义。
- 不让 MMS 解析器负责判断某个 IP、MAC 或通信对是否曾经出现过。
- 不要求仅从 MMS 流量中获得 MAC 可见性。
- 不在本规格中把现有多日志模型替换为单一规范日志。
- 不保证对无法从流量可见名称可靠拆分的对象路径提取 `ld`、`ln`、`do` 或 `da`。
- 不把 Wireshark 启发式 MMS 解码作为 Zeek 必须产出业务日志的依据；如果状态化 ISO 栈从未建立 MMS analyzer 交付，应单独归类。
- 不在新增规范化字段时移除现有原始诊断上下文。

## 补充说明

- 本规格基于 MMS 插件 V1 设计文档中的“字段差距核实表”和“fork 二开功能清单”整理。
- 推荐实现顺序是：先建立共享规范化 helper 和 record 字段，再补 direction/invoke 传递，然后补错误/结果规范化，再补文件服务日志，最后补解析状态映射和回归样本。
- issue tracker 已配置为 GitHub Issues；发布该规格时应创建 GitHub issue，并使用 `ready-for-agent` 标签。
