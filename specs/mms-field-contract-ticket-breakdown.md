# MMS 行为日志字段契约补齐拆票方案

来源规格：`specs/mms-field-contract-gap-spec.md`

发布标签：`ready-for-agent`

## 拆票原则

- 每张票尽量只覆盖一个日志族、一个协议行为或一个测试样本族。
- 票面描述必须说明日志对象、字段集合、枚举语义和验收边界。
- `is_high_risk_operation` 是行为日志派生字段，不是 MMS 协议原始字段；它只由规范化 `operation` 的静态集合计算。
- `parse_status` 只表达解析状态等级；`parse_error` 只表达具体错误原因。
- `parse_status=failed` 表示无法形成具体业务事件，只能写解析状态日志；`parse_status=partial` 表示能形成业务事件，但请求、响应、文件句柄或解析上下文不完整。
- `mms.log` 是 MMS 会话摘要日志，只承载连接/会话级字段，不要求承载 `invoke_id`、`object_path` 等逐操作字段。
- 请求 PDU 可见但响应缺失时，可以产出 `result=unknown`、`parse_status=partial` 的业务日志；不能因为响应缺失而丢弃已观察到的请求行为。
- 对 Zeek `&optional` 字段，缺失时使用 Zeek 日志默认空值表达；不得用字符串 `unknown` 冒充缺失值，除非该字段枚举明确允许 `unknown`。
- 如果现有 PCAP 不覆盖某个协议分支，先记录测试缺口，并允许用最小合成样本或脚本级事件测试覆盖该分支。

## 全局日志约定

- `mms_error.log`：承载无法归入具体业务日志的 MMS 错误，例如未匹配 ConfirmedError、Reject、CancelError、ConcludeError。
- `mms_file_service.log`：承载 MMS 文件服务行为，例如 FileOpen、FileRead、FileClose、FileDelete、FileDirectory、ObtainFile。
- `mms_parse_status.log`：承载无法关联具体业务日志的解析状态，例如无法归属到具体业务对象的 MMS parse weird 或 ISO-only/PRES 分类。

## Tickets

### 1. 抽出 MMS 统一字段填充 helper

**Blocked by**：None，可以立即开始

**What it delivers**：提供一组可复用的字段填充函数，用来统一生成端点字段、结果字段、错误字段、解析状态字段和高风险操作字段，后续所有 MMS 业务日志复用这套逻辑。

**Acceptance criteria**

- [ ] helper 能生成 `src_ip`、`dst_ip`、`src_port`、`dst_port`。
- [ ] helper 能生成 `result`、`error_code`、`diag`、`parse_status`、`parse_error` 的默认值。
- [ ] helper 能基于规范化 `operation` 的静态集合计算 `is_high_risk_operation`。

### 2. 准备 MMS 日志字段契约的 btest 检查方式

**Blocked by**：None，可以立即开始

**What it delivers**：提供统一的 btest 检查方法，用来验证日志文件存在、字段列存在、枚举值合法、空值表达正确，供后续字段补齐 ticket 复用。

**Acceptance criteria**

- [ ] 测试约定能检查指定日志文件是否生成。
- [ ] 测试约定能用 `zeek-cut` 检查字段列是否存在。
- [ ] 测试约定能检查 `result`、`parse_status`、`direction` 等枚举字段只出现允许值。
- [ ] 测试约定能检查允许为空的字段使用一致空值表达。

### 3. 定义 parse_status 与 parse_error 映射表

**Blocked by**：1

**What it delivers**：固定解析状态等级和错误原因枚举，避免后续日志票各自定义解析状态。

**Acceptance criteria**

- [ ] `parse_status` 只允许 `ok`、`partial`、`failed`、`not_applicable`。
- [ ] `parse_error` 至少覆盖 `none`、`mms_parse_error`、`mms_constraint_error`、`pres_parse_error`、`request_response_unmatched`、`file_handle_unmatched`、`iso_stack_incomplete`、`unknown_parse_error`。
- [ ] `parse_status` 与 `parse_error` 的职责边界写清楚：前者是状态等级，后者是具体原因。

### 4. MMS 会话摘要日志输出统一端点与富化占位字段

**Blocked by**：1、2

**What it delivers**：MMS 会话摘要日志输出项目端点字段；它仍然是会话级日志，不承载逐操作字段，也不承载通信关系层的 MAC 或基线事实判断字段。

**Acceptance criteria**

- [ ] MMS 会话摘要日志包含 `src_ip`、`dst_ip`、`src_port`、`dst_port`。
- [ ] `src_mac`、`dst_mac`、`src_ip_seen`、`src_mac_seen`、`mms_ip_pair_seen`、`mms_full_pair_seen` 不进入 MMS 会话摘要日志首批契约，后续由通信关系/基线富化层负责。
- [ ] 不要求 MMS 会话摘要日志输出 `invoke_id` 或 `object_path`。

### 5. MMS 会话摘要日志输出 result/error/parse 状态字段

**Blocked by**：1、2、3、4

**What it delivers**：MMS 会话摘要日志输出会话级 `result`、`error_code`、`parse_status` 和 `parse_error`，覆盖正常 initiate/identify 样本。

**Acceptance criteria**

- [ ] 正常会话摘要行输出 `result=success`、`error_code=none`、`parse_status=ok`、`parse_error=none`。
- [ ] 协议不适用的逐操作字段不出现在 MMS 会话摘要日志中。
- [ ] 现有设备厂商、型号、版本、协议能力字段继续可见。

### 6. 将 direction 传到 MMS 业务事件层

**Blocked by**：1

**What it delivers**：从 MMS PDU 分发点把方向上下文传到服务级、变量级、配对级、文件服务和错误处理事件。

**Acceptance criteria**

- [ ] `is_orig=T` 映射为 `direction=orig_to_resp`。
- [ ] `is_orig=F` 映射为 `direction=resp_to_orig`。
- [ ] `direction` 表达 PDU 流向，不表达业务请求/响应语义。
- [ ] 优先保持旧事件兼容；如必须调整事件签名，同步更新所有 handler 和测试。

### 7. 将 invoke_id 传到 Read 变量日志

**Blocked by**：6

**What it delivers**：Read 成功、失败和 request-only 场景都能在变量日志中看到正确 `invoke_id` 或明确空值。

**Acceptance criteria**

- [ ] Confirmed Read Request/Response 生成的变量日志包含请求对应的 `invoke_id`。
- [ ] Read Response 依赖缓存恢复变量名时，`invoke_id` 与恢复出的变量上下文一致。
- [ ] 无法形成完整响应时不静默丢弃可见请求上下文。

### 8. 将 invoke_id 传到 Write 变量日志

**Blocked by**：6

**What it delivers**：Write 成功、失败和 request-only 场景都能在变量日志中看到正确 `invoke_id`。

**Acceptance criteria**

- [ ] Confirmed Write Request/Response 生成的变量日志包含请求对应的 `invoke_id`。
- [ ] Write Response 依赖缓存恢复写入值时，`invoke_id` 与恢复出的写入上下文一致。
- [ ] 无法形成完整响应时不静默丢弃可见请求上下文。

### 9. 明确 Unconfirmed 业务日志不携带 invoke_id

**Blocked by**：6

**What it delivers**：InformationReport 等 Unconfirmed 业务日志显式保持 `invoke_id` 为空，表达协议层面没有 invoke ID。

**Acceptance criteria**

- [ ] Unconfirmed 业务日志包含 `invoke_id` 字段。
- [ ] Unconfirmed 业务日志的 `invoke_id` 为空值。
- [ ] 空值不被视为解析失败。

### 10. 规范化单变量访问日志的 object_path 与 IEC 61850 拆分字段

**Blocked by**：7、8、9

**What it delivers**：单变量访问日志输出统一 `object_path`，并尽力拆分 `ld`、`ln`、`do`、`da`。

**Acceptance criteria**

- [ ] domain-specific 对象有稳定且可区分的 `object_path` 表达。
- [ ] VMD-specific 和 AA-specific 对象保留作用域信息，避免与 domain-specific 混淆。
- [ ] 可拆分对象路径填充 `ld`、`ln`、`do`、`da`。
- [ ] 不可拆分对象路径保持事件有效，组件字段为空。

### 11. 规范化变量列表访问日志的 object_path 与索引上下文

**Blocked by**：7、8、9

**What it delivers**：变量列表访问日志输出统一 `object_path`，并保留列表名和索引语义。

**Acceptance criteria**

- [ ] 变量列表访问日志包含表示列表对象的 `object_path`。
- [ ] 列表索引继续可见。
- [ ] `object_path` 不丢失列表作用域信息。

### 12. 规范化单变量访问日志的 result/error_code 字段

**Blocked by**：3、10

**What it delivers**：单变量 read/write/report 成功和失败结果统一落到 `result/error_code`。

**Acceptance criteria**

- [ ] 成功事件输出 `result=success`、`error_code=none`。
- [ ] DataAccessError 输出 `result=failure` 和映射后的 `error_code`。
- [ ] 无法映射的错误输出 `error_code=unknown_error`。
- [ ] 原始 `diag` 继续保留。

### 13. 规范化变量列表访问日志的 result/error_code 字段

**Blocked by**：3、11

**What it delivers**：变量列表 read/write/report 成功和失败结果统一落到 `result/error_code`。

**Acceptance criteria**

- [ ] 成功事件输出 `result=success`、`error_code=none`。
- [ ] DataAccessError 输出 `result=failure` 和映射后的 `error_code`。
- [ ] 无法映射的错误输出 `error_code=unknown_error`。
- [ ] 原始 `diag` 继续保留。

### 14. 为变量访问类日志计算行为派生的 high-risk 标识

**Blocked by**：12、13

**What it delivers**：变量访问和变量列表访问日志基于规范化 `operation` 的静态集合计算 `is_high_risk_operation`；该字段是行为日志派生字段，不是 MMS 协议原始字段。

**Acceptance criteria**

- [ ] `write` 等静态高风险操作输出 `is_high_risk_operation=T`。
- [ ] `read`、`report` 等非高风险操作输出 `is_high_risk_operation=F`。
- [ ] 判断不依赖资产清单、点表、SCD、CID 或 ICD。

### 15. 补齐名称列表日志的统一字段契约

**Blocked by**：1、2、3、6

**What it delivers**：GetNameList 成功和错误日志输出统一字段，`object_path` 表示被查询范围或对象上下文。

**Acceptance criteria**

- [ ] 名称列表日志包含端点、方向、`invoke_id`、`operation`、`object_path`、`result`、`error_code`、`diag`、`parse_status`、`parse_error`。
- [ ] 成功响应保留名称列表结果。
- [ ] 错误响应保留原始诊断并输出统一错误码。

### 16. 补齐变量属性日志的统一字段契约

**Blocked by**：1、2、3、6

**What it delivers**：GetVariableAccessAttributes 成功和错误日志输出统一字段；`object_path` 表示被查询变量，响应属性保留在属性字段中。

**Acceptance criteria**

- [ ] 变量属性日志包含统一字段契约要求的字段。
- [ ] `object_path` 来自请求对象，而不是响应属性文本。
- [ ] 成功和错误路径都能落盘。

### 17. 补齐变量列表属性日志的统一字段契约

**Blocked by**：1、2、3、6

**What it delivers**：GetNamedVariableListAttributes 成功和错误日志输出统一字段；`object_path` 表示被查询变量列表，响应成员列表保留在属性字段中。

**Acceptance criteria**

- [ ] 变量列表属性日志包含统一字段契约要求的字段。
- [ ] `object_path` 来自被查询的变量列表名。
- [ ] 响应中的成员变量列表继续可见。

### 18. 补齐已缓存请求的 ConfirmedError 业务落盘

**Blocked by**：12、13、15、16、17

**What it delivers**：ConfirmedError 能命中 read、write、GetNameList、GetVariableAccessAttributes 或 GetNamedVariableListAttributes 缓存时，写入对应业务日志的失败结果。

**Acceptance criteria**

- [ ] 命中缓存的 ConfirmedError 不写入通用错误日志。
- [ ] 对应业务日志输出 `result=failure`、统一 `error_code` 和原始 `diag`。
- [ ] 对应业务日志保留请求侧对象上下文和 `invoke_id`。

### 19. 补齐未匹配 ConfirmedError 的通用错误日志

**Blocked by**：1、2、3、6

**What it delivers**：ConfirmedError 无法命中缓存请求时，写入 `mms_error.log`，避免错误被静默丢弃。

**Acceptance criteria**

- [ ] 未匹配 ConfirmedError 输出 `operation=confirmed_error`。
- [ ] 日志包含 `uid`、端点、`direction`、`invoke_id`、`result=failure`、`error_code`、`diag`。
- [ ] 日志输出 `parse_status=partial`、`parse_error=request_response_unmatched`。

### 20. 补齐 Reject PDU 错误可观测输出

**Blocked by**：19

**What it delivers**：Reject PDU 进入 `mms_error.log`，不新增独立错误日志族。

**Acceptance criteria**

- [ ] Reject 输出 `operation=reject`。
- [ ] Reject 原因映射到 `error_code`，原始原因保留到 `diag`。
- [ ] 结果字段输出 `result=failure`。

### 21. 补齐 CancelError 与 ConcludeError 可观测输出

**Blocked by**：19

**What it delivers**：CancelError 和 ConcludeError 进入 `mms_error.log`，不新增独立错误日志族。

**Acceptance criteria**

- [ ] CancelError 输出 `operation=cancel_error`。
- [ ] ConcludeError 输出 `operation=conclude_error`。
- [ ] 错误原因映射到统一 `error_code`，原始原因保留到 `diag`。

### 22. 实现 FileOpen 文件服务日志与句柄建表

**Blocked by**：1、2、3、6

**What it delivers**：新增 `mms_file_service.log`，FileOpen 直接可见文件名时写入 `file_path`，并建立 `file_handle -> file_path` 的连接内关联。

**Acceptance criteria**

- [ ] FileOpen 输出 `operation=file_open`。
- [ ] 直接可见文件名写入 `file_path`。
- [ ] 文件句柄写入 `file_handle` 并记录关联。
- [ ] 连接结束时清理文件句柄缓存。

### 23. 实现 FileRead/FileClose 文件句柄关联

**Blocked by**：22

**What it delivers**：FileRead/FileClose 通过句柄回填 FileOpen 路径；FileClose 成功或连接结束时释放句柄。

**Acceptance criteria**

- [ ] FileRead 使用句柄回填 `file_path`，但不清理句柄。
- [ ] FileClose 使用句柄回填 `file_path`，成功后清理句柄。
- [ ] 句柄无法关联时输出 `parse_status=partial`、`parse_error=file_handle_unmatched`。

### 24. 实现 FileDelete 与 FileDirectory 文件服务日志

**Blocked by**：1、2、3、6

**What it delivers**：FileDelete 和 FileDirectory 在路径直接可见时写入 `mms_file_service.log`。

**Acceptance criteria**

- [ ] FileDelete 输出 `operation=file_delete` 和 `file_path`。
- [ ] FileDirectory 输出 `operation=file_directory` 和查询路径或目录名。
- [ ] 请求可见但响应缺失时输出 `result=unknown` 或 `parse_status=partial`。

### 25. 实现 ObtainFile 文件服务日志

**Blocked by**：1、2、3、6

**What it delivers**：ObtainFile 输出源路径和目标路径上下文，并使用统一结果字段。

**Acceptance criteria**

- [ ] ObtainFile 输出 `operation=obtain_file`。
- [ ] 源路径和目标路径上下文可见时落盘。
- [ ] 请求可见但响应缺失时输出 `result=unknown` 或 `parse_status=partial`。

### 26. 将 MMS 解析异常纳入业务解析状态日志体系

**Blocked by**：3、5、12、13、15、16、17、19、23、24、25

**What it delivers**：当 MMS 解析过程中出现 `mms_parse_error`、`mms_constraint_error` 等 weird 时，不只依赖 `weird.log` 暴露异常；若异常能关联到具体连接、方向、`invoke_id` 或业务对象，则在对应业务日志中写入 `parse_status=failed|partial` 和具体 `parse_error`；若无法关联到具体业务日志，则写入通用解析状态日志，确保下游能区分“没有业务行为”和“业务行为因解析异常无法完整落盘”。

**Acceptance criteria**

- [ ] 可关联业务上下文的 MMS weird 写入对应业务日志解析字段。
- [ ] 不可关联业务上下文的 MMS weird 写入通用解析状态日志。
- [ ] 解析异常仍保留在 Zeek weird 输出中，不移除原始可观测来源。

### 27. 分类 PRES/ISO-only 样本

**Blocked by**：3

**What it delivers**：presentation parse error 和只到达 ISO 栈的样本被单独分类；未进入 MMS analyzer 的样本不得伪造 MMS operation。

**Acceptance criteria**

- [ ] 未进入 MMS analyzer 的样本不产出 MMS 业务日志。
- [ ] 若可关联连接上下文，可写入通用解析状态日志并设置 `parse_error=iso_stack_incomplete`。
- [ ] 测试说明区分“未进入 MMS analyzer”和“MMS 已进入但业务 handler 未覆盖”。

### 28. 建立成功路径字段契约回归测试

**Blocked by**：12、13、15、16、17

**What it delivers**：覆盖成功 name list、成功变量写、变量属性和变量列表属性样本。

**Acceptance criteria**

- [ ] 至少覆盖一个名称列表成功样本。
- [ ] 至少覆盖一个变量写成功样本。
- [ ] 至少覆盖一个属性类成功样本。
- [ ] 断言日志存在性和关键字段值。

### 29. 建立 request-only 与 unmatched 回归测试

**Blocked by**：18、19、26

**What it delivers**：覆盖 read/write/name list request-only 和请求响应未匹配样本。

**Acceptance criteria**

- [ ] 至少覆盖一个 request-only 样本。
- [ ] 至少覆盖一个请求响应未匹配样本。
- [ ] 断言 `parse_status=partial` 或对应 unmatched 错误原因。

### 30. 建立错误 PDU 字段契约回归测试

**Blocked by**：18、19、20、21、26

**What it delivers**：覆盖 ConfirmedError、Reject、CancelError 和 ConcludeError 等错误样本。

**Acceptance criteria**

- [ ] 至少覆盖一个 ConfirmedError 样本。
- [ ] 至少覆盖一个 Reject、CancelError 或 ConcludeError 样本。
- [ ] 断言 `mms_error.log` 或对应业务失败日志的关键字段。

### 31. 建立文件服务字段契约回归测试

**Blocked by**：22、23、24、25、26

**What it delivers**：覆盖 FileOpen、FileRead、FileClose、FileDelete、FileDirectory、ObtainFile 和句柄关联失败样本。

**Acceptance criteria**

- [ ] 至少覆盖一个文件打开/读取/关闭链路样本。
- [ ] 至少覆盖一个直接路径类文件操作样本。
- [ ] 至少覆盖一个句柄关联失败样本。
- [ ] 断言 `file_path`、`file_handle`、`result`、`parse_status`。

### 32. 建立 ISO-only/PRES 分类回归测试

**Blocked by**：27

**What it delivers**：覆盖只到达 ISO 栈和 PRES parse 分类样本，断言不伪造 MMS 业务日志。

**Acceptance criteria**

- [ ] ISO-only 样本不产出 MMS 业务日志。
- [ ] PRES parse 异常样本被归类到解析状态。
- [ ] 测试说明该类失败不等同于业务 handler 覆盖不足。

### 33. 补充旧字段兼容与迁移说明

**Blocked by**：28、29、30、31、32

**What it delivers**：说明旧字段与新字段的并存/迁移策略，帮助现有消费者迁移。

**Acceptance criteria**

- [ ] V1 保留旧字段并新增规范字段。
- [ ] 本轮不删除 `id`、`success`、`diag`。
- [ ] 文档说明旧字段到 `src_ip/dst_ip/src_port/dst_port`、`result`、`error_code` 的对应关系。
