# Todo: 深化 MMS 请求-响应配对

## Task 1: 固定当前配对行为基线

**Description:** 盘点并运行覆盖 invokeID 配对、request-only、confirmed error、文件配对和成功路径的现有 btest，必要时补一个只覆盖配对路由的窄测试。

**Acceptance criteria:**
- [x] 明确本次改造的测试 seam 是 btest 日志输出和既有事件行为。
- [x] 现有配对相关测试全部通过。
- [ ] 如发现覆盖缺口，新增一条失败优先的 btest。

**Verification:**
- [x] `btest -c testing/btest.cfg tests.mms-read-var-access-invoke-id tests.mms-write-var-access-invoke-id tests.mms-confirmed-error-cached-access tests.mms-success-field-contract`

**Dependencies:** None

**Files likely touched:**
- `testing/tests/*.zeek`
- `testing/Baseline/*`

**Estimated scope:** Small

## Task 2: 建立配对 module 骨架与加载顺序

**Description:** 新增配对 module，先只声明 module、加载 helper、接入 `__load__.zeek`，不迁移行为。

**Acceptance criteria:**
- [x] Zeek 能加载新 module。
- [x] 不改变任何日志输出。
- [x] `events.zeek` 暂无行为迁移。

**Verification:**
- [x] `btest -c testing/btest.cfg tests.show-plugin`
- [x] `btest -c testing/btest.cfg`

**Dependencies:** Task 1

**Files likely touched:**
- `plugin/scripts/pairing.zeek`
- `plugin/scripts/pairing_state.zeek`
- `plugin/scripts/events.zeek`

**Estimated scope:** Small

## Task 3: 迁移 name list / 属性类配对

**Description:** 把 `mms_name_list_requests`、`mms_get_variable_access_attributes_request`、`mms_get_named_variable_list_attributes_request` 及对应 request/response lookup 从 `events.zeek` 移入配对 module。

**Acceptance criteria:**
- [x] 成功响应仍触发 `NameList`、`VariableAccessAttributes`、`NamedVariableListAttributes`。
- [x] 错误响应仍触发对应 `*Error` 事件。
- [x] `events.zeek` 不再持有这三类缓存表。

**Verification:**
- [x] `btest -c testing/btest.cfg tests.mms-name-list-contract tests.mms-var-attributes-contract tests.mms-varlist-attributes-contract tests.mms-success-field-contract`

**Dependencies:** Task 2

**Files likely touched:**
- `plugin/scripts/events.zeek`
- `plugin/scripts/pairing.zeek`

**Estimated scope:** Medium

## Task 4: 迁移 read 配对

**Description:** 把 read 的 confirmed error 请求缓存、`specificationWithResult=false` 响应上下文缓存和响应拆分逻辑移入配对 module。

**Acceptance criteria:**
- [x] read request-only 日志仍保留 invoke_id。
- [x] read response 能按 invokeID 恢复变量名。
- [x] read confirmed error 仍落到变量或变量列表业务日志。

**Verification:**
- [x] `btest -c testing/btest.cfg tests.mms-read-var-access-invoke-id tests.mms-var-read-object-path tests.mms-confirmed-error-cached-access`

**Dependencies:** Task 3

**Files likely touched:**
- `plugin/scripts/events.zeek`
- `plugin/scripts/pairing.zeek`

**Estimated scope:** Medium

## Task 5: 迁移 write 配对

**Description:** 把 write 请求缓存、响应按索引恢复变量名和值、write confirmed error 业务路由移入配对 module。

**Acceptance criteria:**
- [x] write request-only 日志仍保留 invoke_id 和写入值。
- [x] write response 仍按索引恢复变量名和值。
- [x] write confirmed error 仍落到变量或变量列表业务日志。

**Verification:**
- [x] `btest -c testing/btest.cfg tests.mms-write-var-access-invoke-id tests.mms-var-access-result-error-code tests.mms-varlist-access-result-error-code tests.mms-confirmed-error-cached-access`

**Dependencies:** Task 4

**Files likely touched:**
- `plugin/scripts/events.zeek`
- `plugin/scripts/pairing.zeek`

**Estimated scope:** Medium

## Task 6: 迁移 confirmed error 路由

**Description:** 将 `confirmedErrorPDU_evt` 的 lookup ladder 移入配对 module，并显式保留当前匹配优先级：read、write、变量属性、名称列表、变量列表属性、unmatched。

**Acceptance criteria:**
- [x] matched confirmed error 不写入通用错误日志。
- [x] unmatched confirmed error 仍写入 `mms_error.log`。
- [x] 匹配顺序在配对 module 内有单一 owner。

**Verification:**
- [x] `btest -c testing/btest.cfg tests.mms-confirmed-error-cached-access tests.mms-unmatched-confirmed-error-log`

**Dependencies:** Task 5

**Files likely touched:**
- `plugin/scripts/events.zeek`
- `plugin/scripts/pairing.zeek`

**Estimated scope:** Small

## Task 7: 迁移文件请求配对入口

**Description:** 把 FileOpen/FileClose 的 invokeID 请求缓存迁入配对 module；文件句柄 path 状态暂留 `file_service.zeek`，除非后续单独决定深化文件服务模块。

**Acceptance criteria:**
- [x] FileOpen 响应仍能恢复请求文件名并建立句柄。
- [x] FileClose 响应仍能恢复请求句柄。
- [x] 文件句柄 unmatched 行为不变。

**Verification:**
- [x] `btest -c testing/btest.cfg tests.mms-file-open-service-contract tests.mms-file-handle-service-contract`

**Dependencies:** Task 6

**Files likely touched:**
- `plugin/scripts/events.zeek`
- `plugin/scripts/pairing.zeek`
- `scripts/file_service.zeek`

**Estimated scope:** Medium

## Task 8: 收紧 `events.zeek` interface

**Description:** 删除已迁移的 connection 缓存字段、重复注释和旧 implementation，让 `events.zeek` 只保留 PDU 分发和稳定事件声明。

**Acceptance criteria:**
- [x] `events.zeek` 中无 invokeID cache table implementation。
- [x] PDU 分发仍逐类触发入口事件。
- [x] 没有双写、双缓存或死代码。

**Verification:**
- [x] `rg "mms_.*requests|mms_file_open_requests|mms_file_close_requests" plugin/scripts/events.zeek`
- [x] `btest -c testing/btest.cfg`

**Dependencies:** Task 7

**Files likely touched:**
- `plugin/scripts/events.zeek`
- `plugin/scripts/pairing.zeek`

**Estimated scope:** Small

## Task 9: 更新事件分析层文档

**Description:** 更新 `docs/03-event-analysis-layer-outline.md`，把配对 module 作为事件分析层的一等 module 记录下来。

**Acceptance criteria:**
- [x] 文档说明 `events.zeek` 与配对 module 的 seam。
- [x] 文档说明 invokeID 缓存的 owner。
- [x] 文档不再暗示所有缓存都由 `events.zeek` 直接持有。

**Verification:**
- [x] 人工阅读文档与代码一致。

**Dependencies:** Task 8

**Files likely touched:**
- `docs/03-event-analysis-layer-outline.md`

**Estimated scope:** Small
