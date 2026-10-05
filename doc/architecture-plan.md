# Bsvlib 架构设计方案与规划

## 一、 项目背景与设计原则

本项目旨在为 Bitcoin SV（BSV）生态构建一个现代、高性能、低依赖且面向未来的 C# 基础库。借鉴并吸收了 `smartledger-bsv` 等先进设计理念，将 BSV 近年的新技术规范与协议发展（大区块/流式处理、BEEF/BUMP、现代 SPV 验证、新型 BRC 标准等）固化为统一的 .NET 10 程序库。

### 核心设计原则

1. **极致零/低外部依赖（Zero / Minimal Dependencies）**
   - 充分利用 .NET 10 与 C# 最新语言特性以及系统原生 API（`System.Security.Cryptography`、`System.IO.Pipelines`、`System.Buffers`、`System.Numerics`、SIMD、硬件加速等）。
   - 基础功能尽量不引入第三方 NuGet 包，保持代码自给自足与轻量纯粹。

2. **现代化内存与高性能模型（Zero / Low Allocation）**
   - 全面拥抱 `ReadOnlySpan<byte>`、`Span<byte>`、`Memory<byte>`、`ReadOnlySequence<byte>` 与 `ArrayPool<T>`。
   - 数据解析与序列化优先提供 `TryWrite(Span<byte>, out int)` 和 `Parse(ReadOnlySpan<byte>)`。
   - 针对 BSV 大交易与超大区块，采用流式（Streaming）和管线化（Pipelines）读写，避免整块载入内存造成 OOM。

3. **解耦分层与契约化设计**
   - 基础密码学、核心数据模型、SPV 证明、网络协议与应用层标准严格解耦，单向依赖。
   - 模块间通过轻量接口契约交互，方便替换底层实现（如硬件加速的 Secp256k1 引擎）。

4. **命名空间规范**
   - 统一使用 `Bsvlib` 作为根命名空间：
	 - `Bsvlib.Crypto`
	 - `Bsvlib.Core`
	 - `Bsvlib.Spv`
	 - `Bsvlib.P2P`
	 - `Bsvlib.Bips`
	 - `Bsvlib.Bcrs`

---

## 二、 整体架构与项目规划

```plaintext
Bsvlib/
├── doc/
│   └── architecture-plan.md     # 架构设计与实施方案（本文档）
├── src/
│   ├── Bsvlib.Crypto/           # 密码学与椭圆曲线基础库
│   ├── Bsvlib.Core/             # 领域模型、交易、脚本引擎与基础序列化
│   ├── Bsvlib.Spv/              # 现代化 SPV 验证、Merkle 证明、BEEF、BUMP
│   ├── Bsvlib.P2P/              # 点对点节点网络协议通信与流式处理
│   ├── Bsvlib.Bips/             # 通用比特币改进提案（BIP32/39/44/143等）
│   ├── Bsvlib.Bcrs/             # BSV 规范与标准（BRC-8/43 Envelope, Paymail, ARC等）
│   └── Bsvlib/                  # 元包/统一聚合引用入口
└── tests/
	├── Bsvlib.Crypto.Tests/     # 密码学算法矢量测试
	├── Bsvlib.Core.Tests/       # 脚本与交易官方矢量测试
	├── Bsvlib.Spv.Tests/        # SPV/BEEF/BUMP 校验测试
	├── Bsvlib.Bips.Tests/       # BIP 标准测试向量
	└── Bsvlib.Bcrs.Tests/       # BRC 协议编解码与验证测试
```

---

## 三、 各模块详细规划

### 1. `Bsvlib.Crypto`（密码学层）

*定位：纯密码学基础库，提供数字资产运算所需的核心哈希、非对称加密与通用编解码功能。*

- **哈希函数族**：
  - SHA-256、Double-SHA-256（`Hash256`）。
  - RIPEMD-160、`Hash160`（SHA256 后接 RIPEMD160，用于比特币地址与公钥哈希）。
  - HMAC-SHA512（用于 HD 钱包派生）。
- **椭圆曲线算法 (Secp256k1)**：
  - 私钥（`PrivateKey`）、公钥（`PublicKey`，压缩与未压缩形式）。
  - ECDSA 签名计算与验证（支持 RFC 6979 确定性 Nonce 与低 S 规范要求）。
  - Schnorr 签名算法（BSV 规范支持）。
  - ECDH 密钥协商（为链上加密通信提供支持）。
- **编码与格式转换**：
  - `Base58` 与 `Base58Check`（带校验和的比特币地址与 WIF 格式）。
  - `Bech32` / `Bech32m`。
  - `Hex`（高性能十六进制解析与格式化）。
  - `VarInt` / `CompactSize`（可变长整数编解码）。

### 2. `Bsvlib.Core`（核心领域模型与脚本引擎）

*定位：比特币核心概念的强类型抽象、交易组装、签名与脚本栈机执行。*

- **强类型值对象**：
  - `Satoshis`：强类型聪金额封装（防算术溢出、格式转换）。
  - `TxId`：32字节交易哈希表示（处理大端/小端转换）。
  - `OutPoint`：交易输入引用（TxId + Index）。
- **交易与区块模型**：
  - `TxIn`、`TxOut`、`Transaction`（支持动态增删输入输出、序列化/反序列化）。
  - `BlockHeader`、`Block`。
  - BSV 原生 Sighash 算法支持（SighashForkId 等现代多标志位组合计算）。
- **BSV 恢复态脚本引擎（Script Engine）**：
  - `Script` 模型（字节码、操作码列表、流式构造器）。
  - 完整操作码支持（包含 BSV 解除禁令的操作码：`OP_MUL`, `OP_LSHIFT`, `OP_RSHIFT`, `OP_CAT`, `OP_SPLIT`, `OP_NUM2BIN`, `OP_BIN2NUM` 等）。
  - 隔离的栈执行模型（Main Stack、Alt Stack、执行标志与执行状态上下文）。
  - 支持超长脚本与海量数据的流式读取与单步调试。

### 3. `Bsvlib.Spv`（轻客户端与现代证明体系）

*定位：实现现代 BSV 架构下的交易验证、Merkle 路径计算及全新离线验证协议。*

- **Merkle 证明模型**：
  - 经典 Merkle Tree 根节点计算与路径校验。
  - TSC（Technical Standards Committee）标准 Merkle Proof 验证格式。
- **现代化证明格式**：
  - **BUMP** (BSV Unified Merkle Path)：复合树状/多交易 Merkle 证明统一格式。
  - **BEEF** (Background Evaluation Extended Format)：BSV 生态前沿的自包含交易证明包，用于在无须全节点参与下离线完整验证多层父交易及其合法性。
- **轻客户端验证器**：
  - 区块头链（Header Chain）同步与验证。
  - SPV 交易最终确定性（Finality）判别。

### 4. `Bsvlib.P2P`（节点网络交互层）

*定位：高吞吐量、低延迟的节点点对点底层协议交互。*

- **网络传输抽象**：
  - 基于 .NET 10 的 `System.IO.Pipelines` 打造高并发网络流处理器。
  - 纯异步双工连接池管理。
- **协议握手与消息帧**：
  - 协议头（Magic、Command、Length、Checksum）解析。
  - 核心消息：`version`、`verack`、`ping`、`pong`、`addr`、`inv`、`getdata`、`tx`、`block`、`headers`。
- **大区块友好处理**：
  - 支持边读边存边校验（Chunk-based streaming），无需把几百 MB 到 GB 级别的 Block 完整加载至内存。

### 5. `Bsvlib.Bips`（通用规范层）

*定位：行业通用的比特币改进提案标准实现。*

- **BIP-32**：分层确定性钱包（HD Wallet，主密钥派生、子密钥派生、扩展公私钥 xpub/xprv）。
- **BIP-39**：助记词（Mnemonic Words，支持 12/24 词生成、校验与多语言词表支持）。
- **BIP-44**：多账户派生体系（标准路径，如 BSV 专用 `m/44'/236'/0'/...`）。
- **WIF**：钱包导入格式（Wallet Import Format）编码转换。
- **BIP-143**：签名哈希通用计算规范。

### 6. `Bsvlib.Bcrs`（BSV 规范与应用层标准）

*定位：专门承载 BSV 社区特有的 BRC（BSV Request for Comments）协议与现代应用协议。*

- **Envelope 规范 (BRC-8 / BRC-43 等)**：
  - 基于 `OP_FALSE OP_RETURN` 的安全数据载荷与多协议封装。
  - 常见数据协议解析器适配（如 B:// 协议、MAP 协议、AIP 签名协议等）。
- **Paymail (BRC-1 ~ BRC-4)**：
  - 域名解析与 PKI 验证。
  - Public Key 解析与动态地址下发协议。
- **ARC / MAPI 交互模型**：
  - 新一代交易提交（Direct submit to miners）契约。
  - 交易状态生命周期监控（QUEUED, RECEIVED, STORED, ANNOUNCED, MINED, REJECTED）。

---

## 四、 技术实施路线图

| 阶段 | 阶段目标 | 交付物 |
| :--- | :--- | :--- |
| **阶段 1** | 基础设施与密码层 | 搭建工程骨架，建立 `.sln` 与项目依赖关系；完成 `Bsvlib.Crypto`（哈希、Base58、Secp256k1抽象及基础实现）与测试。 |
| **阶段 2** | 核心数据结构与脚本 | 完成 `Bsvlib.Core`（Satoshis、TxIn/TxOut/Transaction 模型、BSV Sighash、全指令脚本引擎）及矢量测试。 |
| **阶段 3** | HD 钱包与标准规范 | 完成 `Bsvlib.Bips`（BIP32/39/44，完整交易构造、签名与广播序列化集成测试）。 |
| **阶段 4** | 现代 SPV 与 BRC 标准 | 完成 `Bsvlib.Spv`（Merkle、BUMP、BEEF）与 `Bsvlib.Bcrs`（Envelope 格式、ARC 数据模型）。 |
| **阶段 5** | P2P 网络层与元包整合 | 完成 `Bsvlib.P2P` 异步管道连接，发布统一的 `Bsvlib` 聚合包与完整范例文档。 |
