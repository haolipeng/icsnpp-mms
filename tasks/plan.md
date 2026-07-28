# Implementation Plan: 深化 MMS 请求-响应配对

## Overview

本计划把 `plugin/scripts/events.zeek` 中分散的 invokeID 缓存、请求响应配对、confirmed error 路由收进一个更深的配对模块。目标不是改变现有日志行为，而是缩小 `events.zeek` 的 interface：它继续承担 `mms_pdu` 分发，但不再让各类缓存表和查找阶梯暴露在同一个浅模块里。测试 seam 保持在 btest 可观察日志输出和配对级事件行为上。

## Current Friction

- `events.zeek` 同时承担 PDU 分发、请求缓存、响应配对、变量拆分、文件句柄入口、confirmed error 路由。
- 每新增一种 confirmed 操作，就要改缓存字段、request handler、response handler、error ladder，多处同步，局部性弱。
- confirmed error 路由依赖一串 `else if invokeID in table`，业务优先级和缓存所有权隐含在控制流里。
- read/write/name list/attribute/file 的配对模式相似，但没有一个统一的 module 承载“按 invokeID 管理请求上下文”这个概念。

## Architecture Decisions

- 新增一个进程内配对 module，放在 `plugin/scripts/`，因为它靠近事件 interface，并拥有 connection 级缓存字段。
- 由于 Zeek 编译时 connection 字段必须先可见，而配对 handler 需要在 `events.zeek` 声明业务事件后再加载，配对 module 采用两个同 module 文件：
  - `plugin/scripts/pairing_state.zeek`：只声明 connection-scoped pairing state。
  - `plugin/scripts/pairing.zeek`：实现请求缓存、响应配对和后续 confirmed error 路由。
- `events.zeek` 保留外部入口 `mms::mms_pdu` 和服务级事件声明，缓存和查找 implementation 移到配对 module。
- 配对 module 的 interface 保持 Zeek event 风格，不引入过度抽象：
  - 请求进入：沿用现有 `readRequest` / `writeRequest` / `getNameListRequest` 等服务级事件。
  - 响应进入：沿用现有 `readResponse` / `writeResponse` / `getNameListResponse` 等服务级事件。
  - 错误进入：沿用现有 `confirmedErrorPDU_evt`。
  - 产出保持既有配对级或变量级事件：`VariableReadResponse`、`NameList`、`VariableAccessAttributesError` 等。
- 迁移采用“replace, don't layer”：每迁走一类缓存，就从 `events.zeek` 删除对应 implementation，而不是在旧逻辑外再包一层。
- 每个 slice 先加或复用 btest 约束，再迁移一类配对逻辑；每个 slice 后完整 btest 仍应通过。

## Task List

### Phase 1: Foundation

- [x] Task 1: 固定当前配对行为基线。
- [x] Task 2: 建立配对 module 骨架与加载顺序。
- [x] Task 3: 迁移 name list / 属性类配对。

### Checkpoint: Foundation

- [x] `btest -c testing/btest.cfg tests.mms-name-list-contract tests.mms-var-attributes-contract tests.mms-varlist-attributes-contract tests.mms-success-field-contract`
- [x] `events.zeek` 中属性类缓存字段和 response lookup 已减少。

### Phase 2: Core Pairing

- [x] Task 4: 迁移 read 配对。
- [x] Task 5: 迁移 write 配对。
- [x] Task 6: 迁移 confirmed error 路由。

### Checkpoint: Core Pairing

- [x] `btest -c testing/btest.cfg tests.mms-read-var-access-invoke-id tests.mms-write-var-access-invoke-id tests.mms-confirmed-error-cached-access tests.mms-unmatched-confirmed-error-log`
- [x] read/write request-only、response pairing、confirmed error 行为不变。

### Phase 3: File Pairing And Cleanup

- [x] Task 7: 迁移文件请求配对入口。
- [x] Task 8: 删除旧缓存字段和重复注释，收紧 `events.zeek` interface。
- [x] Task 9: 更新事件分析层文档。

### Checkpoint: Complete

- [x] `btest -c testing/btest.cfg`
- [x] `events.zeek` 只负责 PDU 到服务级入口分发和事件 interface 声明。
- [x] 配对 module 成为 invokeID 状态和 confirmed error lookup 的唯一 owner。

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Zeek 脚本加载顺序导致事件未声明或重复声明 | High | `events.zeek` 先加载 `pairing_state.zeek` 声明字段，再在事件声明与 dispatcher 后加载 `pairing.zeek` |
| 配对迁移改变日志行顺序 | Medium | 每个 slice 只迁一类操作，使用既有 baseline 检查输出 |
| read/write 多变量索引错配 | High | 优先跑 invoke_id、object_path、confirmed-error-cached 相关测试 |
| confirmed error 优先级改变 | High | 单独把 error ladder 迁移为显式匹配顺序，并保持现有测试 |
| 形成一层浅的转发 module | Medium | 每迁一类逻辑就删除 `events.zeek` 内旧 implementation，避免双层维护 |

## Resolved Decisions

- 配对 module 已放在 `plugin/scripts/`，并拆成 `pairing_state.zeek` 与 `pairing.zeek` 来满足 Zeek 加载顺序。
- 内部入口继续沿用现有服务级事件名称，避免引入一层只转发的 `pairing*` 事件。
- 文件请求的 invokeID 缓存归配对 module；`mms_file_handles` 保留为文件服务业务状态。
