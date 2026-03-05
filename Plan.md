# P2 对齐计划：rbtc → Bitcoin Core bit-by-bit

> P0（测试向量 + P2P 消息）和 P1（共识边缘 + RPC 兼容）已完成。
> 本文档覆盖 P2 级对齐工作：Mempool 策略、钱包精确匹配、CI/Fuzzing。

---

## 审计摘要

| 模块 | 现有行数 | P2 缺口数 | 严重度 |
|------|---------|----------|--------|
| rbtc-mempool | ~670 | 5 | 3 CRITICAL, 2 HIGH |
| rbtc-wallet | ~1800 | 4 | 2 HIGH, 2 MEDIUM |
| CI/Fuzzing | 0 | 3 | ALL HIGH |
| rbtc-net (P2P/过滤) | ~2800 | 4 | 1 HIGH, 3 MEDIUM |

---

## Phase E：Mempool 策略精确匹配

### E1. Package Relay 聚合费率（BIP331）— CRITICAL

**现状**: `accept_package()` 逐个调用 `accept_tx()`，低费率父交易即使子交易补偿也被拒绝。

**缺口**: 无 package 级聚合费率检查。Bitcoin Core 允许 `(parent_fee + child_fee) / (parent_vsize + child_vsize) >= min_relay_fee_rate`。

**文件**: `crates/rbtc-mempool/src/pool.rs:499-554`

**修改方案**:
1. `accept_package()` 中先计算包聚合费率
2. 对于低于 `min_relay_fee_rate` 的单笔父交易，如果包聚合费率满足条件，临时放宽单笔检查
3. 添加 `accept_tx_with_package_context()` 内部方法，接受可选的 `package_fee_rate` 参数
4. 若任何单笔交易失败且非费率原因，整个包原子回滚

**测试**: 构造 parent(fee_rate=0) + child(fee_rate=10) 包，验证包被接受；单独提交 parent 仍被拒绝。

---

### E2. V3 Sibling 驱逐（BIP431）— HIGH

**现状**: `pool.rs:191-199` 当 v3 父交易已有子交易时，无条件拒绝新的子交易。

**缺口**: 应比较新旧子交易费率，若新子更高则驱逐旧子。

**文件**: `crates/rbtc-mempool/src/pool.rs:188-201`

**修改方案**:
```
如果 parent 已有 v3 child:
  找到 existing_child
  如果 new_child.fee_rate > existing_child.fee_rate + min_relay_fee_rate:
    且 new_child.fee >= existing_child.fee:  // 绝对费用也要更高
    驱逐 existing_child
    继续接受 new_child
  否则:
    拒绝 new_child
```

**测试**: v3 parent + child_A(fee=100) → child_B(fee=200) 应替换 child_A；child_C(fee=50) 应被拒绝。

---

### E3. 挖矿分数驱逐（Mining Score Eviction）— HIGH

**现状**: `evict_below_fee_rate()` (pool.rs:414-438) 仅按 `ancestor_fee_rate` 排序驱逐。

**缺口**: Bitcoin Core 使用 `mining_score = min(ancestor_fee_rate, individual_fee_rate)` 作为驱逐优先级。后代信息（`descendant_fees`/`descendant_vsize`）已追踪但未参与驱逐决策。

**文件**: `crates/rbtc-mempool/src/pool.rs:414-438`

**修改方案**:
1. 计算 `mining_score = min(entry.ancestor_fee_rate, entry.fee_rate)`
2. 驱逐时按 `mining_score` 升序排列
3. 驱逐时同时移除该交易的所有后代（避免孤儿交易）
4. 在驱逐循环中使用 `remove_with_descendants()` 辅助函数

**测试**: 插入 tx_A(ancestor_rate=5, individual_rate=1) 和 tx_B(ancestor_rate=1, individual_rate=5)，验证 tx_B 的 mining_score=1 优先被驱逐。

---

### E4. RBF 绝对费用检查（BIP125 Rule 3）— HIGH

**现状**: `pool.rs:139-161` 仅检查费率 (`fee_rate > max_conflict_rate + relay`)。

**缺口**: BIP125 Rule 3 要求替换交易的**绝对费用**必须超过所有被替换交易费用之和。

**文件**: `crates/rbtc-mempool/src/pool.rs:139-161`

**修改方案**:
```rust
let total_conflict_fees: u64 = conflicting.iter()
    .map(|cid| self.entries[cid].fee)
    .sum();
if fee < total_conflict_fees {
    return Err(MempoolError::RbfAbsoluteFeeTooLow(fee, total_conflict_fees));
}
```

**新增错误**: `MempoolError::RbfAbsoluteFeeTooLow(u64, u64)`

**测试**: replaced_tx(1000vB, 10sat/vB=10000sat) → replacement(500vB, 11sat/vB=5500sat) 应被拒绝 (5500 < 10000)。

---

### E5. Sigops 限制执行 — MEDIUM

**现状**: `MAX_STANDARD_TX_SIGOPS_COST` 定义在 `policy.rs:17` 但从未在 `accept_tx()` 中检查。

**文件**: `crates/rbtc-mempool/src/pool.rs` (accept_tx), `crates/rbtc-mempool/src/policy.rs`

**修改方案**:
1. 在 `policy.rs` 添加 `count_sigops(tx) -> u32` 函数
2. 在 `accept_tx()` 的标准性检查之后调用，拒绝超过 16000 的交易
3. 可选：在 `MempoolEntry` 中追踪 sigops，用于祖先链限制

---

## Phase F：钱包精确匹配

### F1. dumpwallet / importwallet — HIGH

**现状**: 仅有单个密钥的 `dump_privkey()` 和 `import_wif()`，无批量操作。

**文件**: `crates/rbtc-wallet/src/wallet.rs`

**修改方案**:

**dumpwallet**:
```rust
pub fn dump_wallet(&self) -> Vec<String> {
    // 每行格式: "{wif} {timestamp} # addr={address} label={label}"
    // 遍历所有 HD 派生地址和导入密钥
}
```

**importwallet**:
```rust
pub fn import_wallet(&mut self, lines: &[String]) -> Result<usize, WalletError> {
    // 解析每行，提取 WIF，调用 import_wif()
    // 返回导入的密钥数量
}
```

**测试**: 创建钱包 → 派生 3 个地址 → dumpwallet → 新钱包 → importwallet → 验证地址一致。

---

### F2. StoredAddressInfo 时间戳 — MEDIUM

**现状**: `wallet_store.rs:21-29` 的 `StoredAddressInfo` 无时间戳字段。

**修改方案**:
1. 添加 `pub created_at: u64` (Unix timestamp) 到 `StoredAddressInfo`
2. `new_address()` 和 `import_wif()` 中设置 `SystemTime::now()`
3. `dumpwallet` 输出中包含时间戳
4. 反序列化兼容：旧数据无 `created_at` 时默认 0

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAddressInfo {
    pub address: String,
    pub addr_type: String,
    pub derivation_path: String,
    pub pubkey_hex: String,
    #[serde(default)]
    pub created_at: u64,
}
```

---

### F3. BnB 废物度量 (Waste Metric) — MEDIUM

**现状**: `tx_builder.rs:63-205` BnB 实现完整，`CHANGE_COST` 正确，但不计算 waste。

**缺口**: Bitcoin Core 在多个 BnB 解中选择 waste 最小的。Waste = Σ(input_fee - long_term_fee) + change_cost_or_excess。

**文件**: `crates/rbtc-wallet/src/tx_builder.rs:63-205`

**修改方案**:
1. 在 BnB 找到有效解时，计算 waste 值
2. 记录 `best_waste` 和 `best_selection`，继续搜索直到耗尽尝试次数
3. 返回 waste 最低的解

---

### F4. 钱包 PSBT 签名集成 — LOW

**现状**: `wallet.rs:525-528` 的 `key_for_script()` 可被 PSBT 使用，但钱包自身无 `sign_psbt()` 方法。PSBT crate (`rbtc-psbt`) 独立存在，RPC 层 `walletprocesspsbt` 已实现。

**评估**: RPC 层已经桥接了 wallet 和 PSBT，功能上可用。建议在 wallet 层添加直接方法以简化 API，但优先级低。

---

## Phase G：持续集成

### G1. GitHub Actions CI — HIGH

**现状**: 无任何 CI 配置。

**新建**: `.github/workflows/ci.yml`

```yaml
内容要点:
- push/PR 触发
- cargo check --workspace
- cargo test --workspace
- cargo clippy --workspace -- -D warnings
- cargo fmt --check
- 矩阵: stable + nightly
- 缓存: ~/.cargo/registry + target/
```

---

### G2. Dockerfile + docker-compose — HIGH

**现状**: 无容器化。集成测试需手动启动 bitcoind。

**新建**:
- `Dockerfile`: 多阶段构建 rbtc 二进制
- `docker-compose.yml`: rbtc + bitcoind (regtest) 双节点
- `scripts/integration-test.sh`: 自动化集成测试脚本

---

### G3. cargo-fuzz 差分模糊测试 — MEDIUM

**现状**: 无 fuzzing 基础设施。

**新建**: `fuzz/` 目录

**目标**:
1. `fuzz_script_eval`: 随机脚本 → 与 Bitcoin Core libconsensus 结果对比
2. `fuzz_tx_decode`: 随机字节 → 解码一致性
3. `fuzz_block_header`: 随机 header 字节 → PoW/结构验证一致性

---

## Phase H：P2P 过滤与服务位对齐

### H1. ServiceFlags 枚举化 — HIGH

**现状**: `message.rs:180,188` 服务位硬编码为裸数字 `0x0401`，无语义定义。

**缺口**: Bitcoin Core 使用枚举定义所有服务位，便于按位组合、检查和日志输出。当前无法按名称检查 peer 是否支持某能力。

**文件**: `crates/rbtc-net/src/message.rs`

**修改方案**:
```rust
bitflags::bitflags! {
    pub struct ServiceFlags: u64 {
        const NODE_NETWORK         = 1 << 0;  // BIP37/full node
        const NODE_BLOOM           = 1 << 2;  // BIP111 (deprecated, 不设置)
        const NODE_WITNESS         = 1 << 3;  // BIP144
        const NODE_COMPACT_FILTERS = 1 << 6;  // BIP157
        const NODE_NETWORK_LIMITED = 1 << 10; // BIP159
    }
}
```
1. 添加 `bitflags` 依赖到 `rbtc-net/Cargo.toml`
2. 将所有 `0x0401` / `1033` 替换为 `ServiceFlags::NODE_NETWORK | ServiceFlags::NODE_WITNESS`
3. Version 消息发送/接收时使用 `ServiceFlags`
4. 日志中打印 flag 名称（如 `"NODE_NETWORK|NODE_WITNESS"`）

**测试**: 构造 version 消息 → 编解码 → 验证 flags 解析正确。

---

### H2. BIP157/158 Compact Block Filters P2P 层 — MEDIUM

**现状**: GCS (Golomb-Coded Set) 算法已完整实现并通过 Bitcoin Core 测试向量 (`blockfilter_tests.rs`)，但：
- 未从 `rbtc-consensus` 导出为公开 API
- 无 P2P 消息：`getcfilters`/`cfilter`/`getcfheaders`/`cfheaders`/`getcfcheckpt`/`cfcheckpt` 全部缺失
- 未设置 `NODE_COMPACT_FILTERS` (0x40) 服务位
- 无存储层：未在 RocksDB 中持久化已计算的 filter

**文件**:
- GCS 实现: `crates/rbtc-consensus/tests/blockfilter_tests.rs` (需提取到 `src/`)
- P2P 消息: `crates/rbtc-net/src/message.rs`
- 存储: `crates/rbtc-storage/src/db.rs`

**修改方案**:
1. **提取 GCS 到公开模块**: 将 `blockfilter_tests.rs` 中的 `build_basic_filter()`、`golomb_rice_encode`、`BitWriter` 等提取到 `crates/rbtc-consensus/src/blockfilter.rs`，并在 `lib.rs` 中导出
2. **存储层**: 在 `db.rs` 添加 `CF_BLOCK_FILTERS` 列族，`block_store.rs` 添加 `put_filter()`/`get_filter()` 方法
3. **P2P 消息**: 在 `message.rs` 的 `NetworkMessage` 枚举中添加 6 个消息类型 + 编解码
4. **服务位**: 依赖 H1 的 `ServiceFlags` 枚举，条件设置 `NODE_COMPACT_FILTERS`
5. **handler**: 在 `peer_manager.rs` 中添加 `getcfilters` → 查存储 → 回复 `cfilter` 的处理逻辑
6. **区块连接时**: 在新区块存储后自动计算并持久化 basic filter

**测试**:
- 单元测试：构造已知区块 → 计算 filter → 与测试向量比对
- P2P 测试：模拟 `getcfilters` 请求 → 验证返回正确 `cfilter`

---

### H3. BIP35 mempool 消息响应 — MEDIUM

**现状**: `mempool` 消息可解析，handler 触发 `MempoolRequested` 事件，但未回复 inv 列表。

**文件**: `crates/rbtc-net/src/peer_manager.rs`

**修改方案**:
1. 收到 `MempoolRequested` 事件后，收集 mempool 中所有 txid
2. 构造 `inv` 消息（`InvType::Tx` 或 `InvType::WitnessTx`，取决于 peer 是否支持 wtxidrelay）
3. 分批发送（每个 inv 消息最多 50000 条）

**测试**: 向 rbtc 发送 `mempool` 消息 → 验证返回包含当前 mempool 所有 txid 的 inv。

---

### H4. sendheaders 偏好路由 — LOW

**现状**: `peer_manager.rs:585` 追踪了 peer 的 sendheaders 偏好，但广播新区块时不根据偏好选择 headers vs inv。

**修改方案**: 广播新区块时检查 peer 是否发送过 `sendheaders`，是则发 `headers` 消息，否则发 `inv(block)`。

---

## 遗留缺口

### N1. getpeerinfo RPC 填充 — LOW
**现状**: 返回空数组，应从 peer_manager 获取实际连接信息。

---

## 执行顺序

```
E4（RBF 绝对费用）→ E2（V3 sibling 驱逐）→ E3（mining score 驱逐）
→ E1（package relay 聚合费率）→ E5（sigops 限制）
→ H1（ServiceFlags 枚举）→ H2（BIP157/158 P2P 层）→ H3（mempool 响应）→ H4（sendheaders 路由）
→ F2（时间戳）→ F1（dumpwallet/importwallet）→ F3（waste metric）
→ G1（GitHub Actions）→ G2（Docker）→ G3（cargo-fuzz）
```

**理由**:
- E4/E2/E3 是独立修改，互不依赖，可快速完成
- E1 最复杂（需修改 accept_tx 签名），放在理解充分后
- H1 是 H2 的前置依赖（ServiceFlags 枚举化后才能正确设置 NODE_COMPACT_FILTERS）
- H2 依赖 H1 的 ServiceFlags + 需要 GCS 代码从 tests 提取到 src
- F2 是 F1 的前置依赖
- G 系列独立于代码修改，放最后

---

## 验证方案

| 项目 | 验证方式 |
|------|---------|
| E1-E5 | `cargo test -p rbtc-mempool` 全部通过 + 每个修改至少 2 个针对性测试 |
| H1-H4 | `cargo test -p rbtc-net` 全部通过 + ServiceFlags 编解码 + BIP157 消息 roundtrip |
| F1-F3 | `cargo test -p rbtc-wallet` 全部通过 + dumpwallet/importwallet roundtrip |
| G1 | GitHub push 后 CI 绿色 |
| G2 | `docker-compose up` 后 rbtc 与 bitcoind regtest 完成握手 |
| G3 | `cargo fuzz run` 10 分钟无 crash |
| 全量 | `cargo test --workspace` 450+ 测试全部通过 |
