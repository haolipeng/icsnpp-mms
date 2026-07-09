# MMS 插件编译安装与测试 Quickstart

本文档用于记录 MMS 插件及其依赖的编译、安装、测试流程，以及 Zeek 回放 PCAP 后日志文件的查看位置。

## 1. 环境路径

运行命令需要用到的路径如下：

```text
Zeek 安装路径：/usr/local/zeek
MMS 插件源码：/home/work/openSource/ics-security/icsnpp-mms
PCAP 样本目录：/home/work/pcaps_dataset
测试输出目录：/tmp/icsnpp-mms-test-output
```

检查当前 Zeek 环境：

```bash
which zeek
zeek -v
zeek-config --prefix
```

## 2. 安装 MMS 依赖

MMS over TCP/102 依赖 ISO 协议栈。先安装 TPKT、COTP、SESS、PRES、ACSE：

```bash
zkg install --force https://github.com/DINA-community/icsnpp-tpkt
zkg install --force https://github.com/DINA-community/icsnpp-cotp
zkg install --force https://github.com/DINA-community/icsnpp-sess
zkg install --force https://github.com/DINA-community/icsnpp-pres
zkg install --force https://github.com/DINA-community/icsnpp-acse
```

验证依赖安装状态：

```bash
zkg list | rg -i 'tpkt|cotp|sess|pres|acse'
zeek -NN | rg -i 'TPKT|COTP|SESS|PRES|ACSE'
```

## 3. 编译安装 MMS 插件

将 MMS 插件统一安装到 `/usr/local/zeek` 对应的 Zeek 插件目录：

```bash
cd /home/work/openSource/ics-security/icsnpp-mms

rm -rf build
./configure --with-bifcl=/usr/local/zeek/bin/bifcl
cmake --build build -j"$(nproc)"
sudo cmake --build build --target install
```

验证 MMS 插件是否可见：

```bash
zeek -NN | rg -i 'MMS|ISO_1_0_9506'
```

## 4. 运行 MMS 插件测试

### 自带 btest

```bash
cd /home/work/openSource/ics-security/icsnpp-mms/testing
PATH=/home/work/openSource/ics-security/icsnpp-mms/build:$PATH btest -c btest.cfg
```

### 单个 PCAP 回放

Zeek 会把日志写到执行 `zeek` 命令时所在的当前目录。下面示例将日志写到 `/tmp/icsnpp-mms-test-output/client-server-mms`：

```bash
OUT=/tmp/icsnpp-mms-test-output/client-server-mms
rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"

zeek -Cr /home/work/pcaps_dataset/client-server-mms.pcap \
  packages \
  /home/work/openSource/ics-security/icsnpp-mms/scripts
```

### 批量 PCAP 回放

下面脚本会回放 MMS 需求文档中的核心 PCAP，并打印每个样本生成了哪些 `.log` 文件及其数据行数。

```bash
OUT=/tmp/icsnpp-mms-test-output
rm -rf "$OUT"
mkdir -p "$OUT"

PCAPS=(
  /home/work/pcaps_dataset/client-server-mms.pcap
  /home/work/pcaps_dataset/client-server-mms-clean.pcap
  /home/work/pcaps_dataset/iec61850_get_name_list.pcap
  /home/work/pcaps_dataset/get_name_list_full_response.pcap
  /home/work/pcaps_dataset/iec61850_read.pcap
  /home/work/pcaps_dataset/mms-readRequest.pcap
  /home/work/pcaps_dataset/iec61850_write.pcap
  /home/work/pcaps_dataset/mms_write/write_02_domain_boolean_success_response.pcap
  /home/work/pcaps_dataset/mms_file_transfer/iec61850_mms_file_download.pcap
  /home/work/pcaps_dataset/mms_file_transfer/iec61850_mms_file_upload.pcap
  /home/work/pcaps_dataset/initiate_error.pcap
  /home/work/pcaps_dataset/conclude_error.pcap
)

for pcap in "${PCAPS[@]}"; do
  name=$(basename "$pcap" .pcap)
  run_dir="$OUT/$name"
  rm -rf "$run_dir"
  mkdir -p "$run_dir"

  (
    cd "$run_dir"
    zeek -Cr "$pcap" \
      packages \
      /home/work/openSource/ics-security/icsnpp-mms/scripts \
      > zeek.stdout 2> zeek.stderr
  )

  status=$?
  logs=$(find "$run_dir" -maxdepth 1 -name '*.log' -printf '%f ' | sort)
  printf '%s | exit=%s | logs=%s\n' "$pcap" "$status" "$logs"

  for log in \
    conn.log \
    tpkt.log \
    cotp_conn.log \
    sess.log \
    pres.log \
    acse.log \
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
    printf '  stderr='
    tr '\n' ' ' < "$run_dir/zeek.stderr" | cut -c1-300
    printf '\n'
  fi
done
```

## 5. 查看日志文件

Zeek 会把日志写到执行 `zeek` 命令时所在的当前目录。如果先 `cd` 到 `/tmp/icsnpp-mms-test-output/client-server-mms` 后运行 Zeek，则日志就在该目录下。

常见日志文件如下：

```text
conn.log                   Zeek TCP 连接日志
tpkt.log                   TPKT 层日志
cotp_conn.log              COTP 层日志
sess.log                   Session 层日志
pres.log                   Presentation 层日志
acse.log                   ACSE 层日志
mms.log                    MMS 会话/设备识别相关日志
mms_name_list.log          GetNameList 相关日志
mms_var_access.log         Read/Write 变量访问日志
mms_varlist_access.log     变量列表访问日志
mms_var_attributes.log     GetVariableAccessAttributes 日志
mms_varlist_attributes.log GetNamedVariableListAttributes 日志
weird.log                  解析异常日志
```

查看日志文件：

```bash
ls -lh
zeek-cut < mms.log
zeek-cut operation variable success diag < mms_var_access.log
zeek-cut name addl < weird.log
```

`zeek-cut operation variable success diag < mms_var_access.log` 仅适用于 `mms_var_access.log` 存在且包含对应字段的情况。
