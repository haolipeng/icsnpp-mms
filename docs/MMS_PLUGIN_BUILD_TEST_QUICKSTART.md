# MMS 插件编译与 PCAP 测试 Quickstart

本文档记录当前仓库推荐的 MMS 端到端测试方式：使用本地 Zeek
源码构建环境和 `/home/work/openSource/ics-security` 下的本地协议插件，
回放 `/home/work/pcaps_dataset` 中的 MMS PCAP。

不要使用 `@load packages`，也不要从
`/usr/local/zeek/share/zeek/site/packages` 加载 TPKT/COTP/ACSE。那些路径
可能包含旧脚本，容易和本仓库当前事件签名冲突。

## 1. 路径

```text
Zeek 源码：       /home/work/openSource/ics-security/zeek-8.0.8
PCAP 样本目录：  /home/work/pcaps_dataset
测试输出目录：   /tmp/icsnpp-mms-test-output

TPKT：           /home/work/openSource/ics-security/icsnpp-tpkt
COTP：           /home/work/openSource/ics-security/icsnpp-cotp
SESS：           /home/work/openSource/ics-security/icsnpp-sess
PRES：           /home/work/openSource/ics-security/icsnpp-pres
ACSE：           /home/work/openSource/ics-security/icsnpp-acse
MMS：            /home/work/openSource/ics-security/icsnpp-mms
```

常用变量：

```bash
ROOT=/home/work/openSource/ics-security
ZEEK_DIST=$ROOT/zeek-8.0.8
ZEEK=$ZEEK_DIST/build/src/zeek
SPICYZ=$ZEEK_DIST/build/src/spicy/spicyz/spicyz
BIFCL=$ZEEK_DIST/build/auxil/bifcl/bifcl
PCAPS=/home/work/pcaps_dataset
OUT=/tmp/icsnpp-mms-test-output
```

## 2. 构建本地依赖

TPKT、COTP、SESS 是 Spicy analyzer，构建后产物是 `.hlto`：

```bash
ROOT=/home/work/openSource/ics-security
SPICYZ=$ROOT/zeek-8.0.8/build/src/spicy/spicyz/spicyz

for plugin in icsnpp-tpkt icsnpp-cotp icsnpp-sess; do
  cd "$ROOT/$plugin"
  rm -rf build
  cmake -S . -B build -DSPICYZ="$SPICYZ"
  cmake --build build -j"$(nproc)"
done
```

PRES、ACSE、MMS 是动态 Zeek 插件：

```bash
ROOT=/home/work/openSource/ics-security
ZEEK_DIST=$ROOT/zeek-8.0.8
BIFCL=$ZEEK_DIST/build/auxil/bifcl/bifcl

for plugin in icsnpp-pres icsnpp-acse icsnpp-mms; do
  cd "$ROOT/$plugin"
  rm -rf build
  ./configure --zeek-dist="$ZEEK_DIST" --with-bifcl="$BIFCL"
  cmake --build build -j"$(nproc)"
done
```

检查关键产物：

```bash
ls -lh \
  $ROOT/icsnpp-tpkt/build/tpkt.hlto \
  $ROOT/icsnpp-cotp/build/cotp.hlto \
  $ROOT/icsnpp-sess/build/sess.hlto \
  $ROOT/icsnpp-pres/build/lib/OSS-PRES.linux-x86_64.so \
  $ROOT/icsnpp-acse/build/lib/OSS-ACSE.linux-x86_64.so \
  $ROOT/icsnpp-mms/build/lib/OSS-MMS.linux-x86_64.so
```

## 3. 运行 btest

```bash
cd /home/work/openSource/ics-security/icsnpp-mms/testing
btest -c btest.cfg
```

## 4. 单个 PCAP 回放

下面命令使用本地插件链回放一个 MMS Read 样本。日志写入 `$OUT`。

```bash
ROOT=/home/work/openSource/ics-security
ZEEK_DIST=$ROOT/zeek-8.0.8
ZEEK=$ZEEK_DIST/build/src/zeek
PCAPS=/home/work/pcaps_dataset
OUT=/tmp/icsnpp-mms-test-output/iec61850_read

rm -rf "$OUT"
mkdir -p "$OUT"

ZEEKPATH_BASE=$("$ZEEK_DIST/build/zeek-path-dev")
ZEEKPATH="$ZEEKPATH_BASE:$ROOT/icsnpp-tpkt/scripts:$ROOT/icsnpp-cotp/scripts:$ROOT/icsnpp-sess/scripts:$ROOT/icsnpp-pres/plugin/scripts:$ROOT/icsnpp-pres/scripts:$ROOT/icsnpp-acse/plugin/scripts:$ROOT/icsnpp-acse/scripts:$ROOT/icsnpp-mms/plugin/scripts:$ROOT/icsnpp-mms/scripts"
ZEEK_PLUGIN_PATH="$ROOT/icsnpp-mms/build:$ROOT/icsnpp-pres/build:$ROOT/icsnpp-acse/build"

(
  cd "$OUT"
  ZEEKPATH="$ZEEKPATH" ZEEK_PLUGIN_PATH="$ZEEK_PLUGIN_PATH" \
    "$ZEEK" -Cr "$PCAPS/iec61850_read.pcap" \
      "$ROOT/icsnpp-tpkt/build/tpkt.hlto" \
      "$ROOT/icsnpp-cotp/build/cotp.hlto" \
      "$ROOT/icsnpp-sess/build/sess.hlto" \
      "$ROOT/icsnpp-tpkt/scripts" \
      "$ROOT/icsnpp-cotp/scripts" \
      "$ROOT/icsnpp-sess/scripts" \
      "$ROOT/icsnpp-pres/plugin/scripts/__preload__.zeek" \
      "$ROOT/icsnpp-pres/scripts" \
      "$ROOT/icsnpp-acse/plugin/scripts/__preload__.zeek" \
      "$ROOT/icsnpp-acse/plugin/scripts/events.zeek" \
      "$ROOT/icsnpp-acse/scripts" \
      "$ROOT/icsnpp-mms/plugin/scripts/__preload__.zeek" \
      "$ROOT/icsnpp-mms/plugin/scripts/events.zeek" \
      "$ROOT/icsnpp-mms/scripts" \
      > zeek.stdout 2> zeek.stderr
)
```

查看生成日志：

```bash
find "$OUT" -maxdepth 1 -name '*.log' -printf '%f\n' | sort
zeek-cut operation variable object_path ld ln do da success invoke_id \
  < "$OUT/mms_var_access.log"
```

## 5. 批量 PCAP 回放

下面脚本只覆盖 MMS 相关核心样本，不包含 GOOSE、Profinet、S7 等其它协议。

```bash
ROOT=/home/work/openSource/ics-security
ZEEK_DIST=$ROOT/zeek-8.0.8
ZEEK=$ZEEK_DIST/build/src/zeek
PCAPS=/home/work/pcaps_dataset
OUT=/tmp/icsnpp-mms-test-output

rm -rf "$OUT"
mkdir -p "$OUT"

ZEEKPATH_BASE=$("$ZEEK_DIST/build/zeek-path-dev")
ZEEKPATH="$ZEEKPATH_BASE:$ROOT/icsnpp-tpkt/scripts:$ROOT/icsnpp-cotp/scripts:$ROOT/icsnpp-sess/scripts:$ROOT/icsnpp-pres/plugin/scripts:$ROOT/icsnpp-pres/scripts:$ROOT/icsnpp-acse/plugin/scripts:$ROOT/icsnpp-acse/scripts:$ROOT/icsnpp-mms/plugin/scripts:$ROOT/icsnpp-mms/scripts"
ZEEK_PLUGIN_PATH="$ROOT/icsnpp-mms/build:$ROOT/icsnpp-pres/build:$ROOT/icsnpp-acse/build"

LOADS=(
  "$ROOT/icsnpp-tpkt/build/tpkt.hlto"
  "$ROOT/icsnpp-cotp/build/cotp.hlto"
  "$ROOT/icsnpp-sess/build/sess.hlto"
  "$ROOT/icsnpp-tpkt/scripts"
  "$ROOT/icsnpp-cotp/scripts"
  "$ROOT/icsnpp-sess/scripts"
  "$ROOT/icsnpp-pres/plugin/scripts/__preload__.zeek"
  "$ROOT/icsnpp-pres/scripts"
  "$ROOT/icsnpp-acse/plugin/scripts/__preload__.zeek"
  "$ROOT/icsnpp-acse/plugin/scripts/events.zeek"
  "$ROOT/icsnpp-acse/scripts"
  "$ROOT/icsnpp-mms/plugin/scripts/__preload__.zeek"
  "$ROOT/icsnpp-mms/plugin/scripts/events.zeek"
  "$ROOT/icsnpp-mms/scripts"
)

MMS_PCAPS=(
  "$PCAPS/client-server-mms.pcap"
  "$PCAPS/client-server-mms-clean.pcap"
  "$PCAPS/iec61850_full_session.pcap"
  "$PCAPS/iec61850_get_name_list.pcap"
  "$PCAPS/get_name_list_full_response.pcap"
  "$PCAPS/iec61850_get_variable_access_attributes.pcap"
  "$PCAPS/iec61850_get_named_variableList_attributes.pcap"
  "$PCAPS/iec61850_read.pcap"
  "$PCAPS/iec61850_read_variable_list_name.pcap"
  "$PCAPS/mms-readRequest.pcap"
  "$PCAPS/read_response_with_data.pcap"
  "$PCAPS/iec61850_write.pcap"
  "$PCAPS/mms_write/write_02_domain_boolean_success_response.pcap"
  "$PCAPS/mms_write/write_04_variable_list_name_unsigned_success.pcap"
  "$PCAPS/unconfirmed_information_report.pcap"
  "$PCAPS/mms_file_transfer/iec61850_mms_file_download.pcap"
  "$PCAPS/mms_file_transfer/iec61850_mms_file_upload.pcap"
)

failures=0

for pcap in "${MMS_PCAPS[@]}"; do
  name=$(basename "$pcap" .pcap)
  run_dir="$OUT/$name"
  rm -rf "$run_dir"
  mkdir -p "$run_dir"

  (
    cd "$run_dir"
    ZEEKPATH="$ZEEKPATH" ZEEK_PLUGIN_PATH="$ZEEK_PLUGIN_PATH" \
      "$ZEEK" -Cr "$pcap" "${LOADS[@]}" > zeek.stdout 2> zeek.stderr
  )

  status=$?
  [ "$status" -eq 0 ] || failures=$((failures + 1))
  printf '%s | exit=%s\n' "$name" "$status"

  for log in \
    mms.log \
    mms_name_list.log \
    mms_var_access.log \
    mms_varlist_access.log \
    mms_var_attributes.log \
    mms_varlist_attributes.log \
    weird.log; do
    if [ -f "$run_dir/$log" ]; then
      lines=$(grep -vc '^#' "$run_dir/$log" || true)
      printf '  %s data_lines=%s\n' "$log" "$lines"
    fi
  done

  if [ -s "$run_dir/zeek.stderr" ]; then
    grep -v 'Duplicate Zeekygen script documentation' "$run_dir/zeek.stderr" \
      | sed 's/^/  stderr: /' \
      | head -n 5
  fi
done

printf 'failures=%s output_dir=%s\n' "$failures" "$OUT"
exit "$failures"
```

## 6. 日志抽查

常见日志：

```text
tpkt.log                   TPKT 层日志
cotp_conn.log              COTP 层日志
sess.log                   SESS 层日志
pres.log                   PRES 层日志
acse.log                   ACSE 层日志
mms.log                    MMS 会话摘要日志
mms_name_list.log          GetNameList 日志
mms_var_access.log         单变量 Read/Write/Report 日志
mms_varlist_access.log     变量列表 Read/Write/Report 日志
mms_var_attributes.log     GetVariableAccessAttributes 日志
mms_varlist_attributes.log GetNamedVariableListAttributes 日志
weird.log                  解析异常日志
```

单变量字段抽查：

```bash
zeek-cut operation variable object_path ld ln do da success invoke_id \
  < "$OUT/iec61850_read/mms_var_access.log"
```

变量列表字段抽查：

```bash
zeek-cut operation listname object_path listindex success invoke_id \
  < "$OUT/write_04_variable_list_name_unsigned_success/mms_varlist_access.log"
```

解析异常抽查：

```bash
zeek-cut name addl < "$OUT/iec61850_read/weird.log"
```

`weird.log` 中出现 `mms_parse_error` 不一定代表 Zeek 运行失败。先看回放命令
exit code；如果 exit 为 0 且业务日志已生成，说明本轮 smoke test 已跑通，
具体解析覆盖问题可另开任务分析。

## 7. 常见问题

### 误加载旧 packages

如果 stderr 出现类似下面的错误，通常是混用了旧版 `packages` 或
`/usr/local/zeek/share/zeek/site/packages`：

```text
use of undeclared alternate prototype
```

处理方式：

- 不要在命令中写 `packages`。
- 不要加载 `/usr/local/zeek/share/zeek/site/packages/icsnpp-*`。
- 确认 `ZEEKPATH` 和命令参数都指向 `/home/work/openSource/ics-security` 下的本地插件。

### 缺少 TPKT/COTP/SESS analyzer

如果只生成 `conn.log`、`tpkt.log` 或 `cotp_conn.log`，但没有上层
`sess.log`、`pres.log`、`acse.log`、`mms.log`，检查是否加载了：

```text
icsnpp-tpkt/build/tpkt.hlto
icsnpp-cotp/build/cotp.hlto
icsnpp-sess/build/sess.hlto
```

以及对应的本地 scripts 目录。
