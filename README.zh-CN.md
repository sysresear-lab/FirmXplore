# FirmXplore

[English](README.md) | **简体中文**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-runtime-blue)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](pyproject.toml)
[![arXiv](https://img.shields.io/badge/arXiv-coming%20soon-b31b1b)](#)
[![Reports](https://img.shields.io/badge/reports-Markdown%20%7C%20HTML%20%7C%20JSON-purple)](#报告)

**一种由大语言模型驱动的固件安全分析系统。**

FirmXplore 是一个自动化、证据驱动的固件安全分析智能体。它在确定性的安全控制和预算限制下，结合固件提取、规范根文件系统验证、真实无头二进制分析、跨组件证据关联、有界运行时验证以及模型服务辅助调查。

当证据不足时，FirmXplore 不会生成利用代码、探测公共目标或虚构漏洞发现。

## 🧭 概览

FirmXplore 将固件镜像转换为可复现的分析工作区，并明确区分静态推理、运行时观察和最终结论。

<p align="center">
  <img src="assets/architecture.png" alt="FirmXplore 证据驱动的固件分析架构" width="100%">
</p>

<p align="center">
  <sub><b>图 1.</b> FirmXplore 证据驱动的固件分析架构。</sub>
</p>

模型服务辅助调查是规划与决策层。模型服务通过 FirmXplore 控制器访问已注册的结构化工具，不能获得任意 Shell、Docker、QEMU 或进程执行工具。

## ✨ 核心特性

- 使用 Docker/binwalk 恢复根文件系统，支持归档内嵌固件回退，并通过 `sasquatch` 恢复旧版 LZMA SquashFS。
- 规范 RootFS 验证、ELF 清单、架构检测和任务工作区管理。
- 面向高价值静态目标的二进制优先级排序。
- 容器化 Ghidra 分析并生成函数、导入项和导出项等产物。
- 组件图构建与攻击面建模。
- 基于启动脚本、服务配置、Web 路由布局和 Ghidra 证据的通用静态攻击面发现，不依赖特定服务后端。
- 面向安全相关上下文的证据化源—汇关联；运行时来源不可用时采用静态回退。
- 确定性的假设合成、验证优先级排序和有界调查循环。
- 面向选定服务与应用验证路径的安全运行时重建。
- FastCGI/服务验证，并生成记录来源的 `DynamicEvidence`。
- 通过结构化输出和受控工具调用实现模型服务辅助调查。
- 模型服务失败时进行重试、指数退避和降级模式回退。
- 记录每次模型服务 HTTP 调用的 token 用量。
- 生成 JSON、Markdown 和本地离线 HTML 报告。
- 支持恢复、状态查询、清理以及显式重新生成报告。

## 🔄 分析流程

FirmXplore 采用以证据为中心的调查流程。固件准备阶段缩小搜索空间，静态分析生成有明确证据支撑的假设，有界动态验证则在假设能够影响最终发现之前收集真实观察。

<p align="center">
  <img src="assets/workflow.png" alt="FirmXplore 端到端调查流程" width="100%">
</p>

<p align="center">
  <sub><b>图 2.</b> FirmXplore 端到端调查流程。</sub>
</p>

该流程采用保守解释原则：可达性不等同于可利用性，源和汇的存在不能自动证明数据流，运行时重建也不能作为厂商原始启动行为一致性的证明。

## 🚀 快速开始

### 📦 环境要求

- Python 3.10 或更高版本。
- 兼容 Docker Engine 的运行环境。
- 已测试环境：安装 Docker Desktop 的 Windows 10/11。
- 默认容器化深度静态分析后端不要求宿主机安装 Ghidra。
- 默认容器化深度静态分析后端不要求宿主机安装 Java 21。

### 🛠️ 安装

FirmXplore 当前不作为 PyPI 软件包提供安装说明，请从仓库安装：

```bash
git clone https://github.com/iceflower-lab/FirmXplore.git
cd FirmXplore
python -m pip install -e .
```

面向用户的控制台命令为 `firmxplore`。为保持兼容性，内部 Python 包名仍为 `fwagent`；后续版本将逐步迁移到公开导入路径 `firmxplore`。

### 🔍 分析固件

```bash
firmxplore analyze firmware.bin
```

默认情况下，FirmXplore 会在 `workspace/` 下创建任务，并在 `workspace/<task-id>/reports/` 下生成报告。

高级示例：

```bash
firmxplore analyze firmware.bin --workspace workspace --task-id my-analysis --timeout 1200 --report-format json,md,html
```

### 📊 状态与报告

```bash
firmxplore status my-analysis --workspace workspace
firmxplore report my-analysis --workspace workspace --format json,md,html
```

开发者回退命令：

```bash
python -m fwagent.cli analyze firmware.bin --workspace workspace --task-id my-analysis
```

### 🎛️ 分析模式

FirmXplore 支持以下分析范围：

**确定性静态分析（默认）：**

```bash
firmxplore analyze firmware.bin
```

执行提取、RootFS 清单、Ghidra 分析、组件关联、攻击面发现、污点关联、假设合成和报告生成，不执行动态验证。

**静态分析 + 模型服务辅助调查：**

```bash
firmxplore analyze firmware.bin --provider-backed
```

在确定性流水线上增加有界 LLM 调查循环（PiAgent）。模型服务只能接收结构化工具，不能访问 Shell、Docker 或进程执行能力。

**显式禁用动态验证：**

```bash
firmxplore analyze firmware.bin --no-dynamic
```

跳过 `INVESTIGATION` 和 `DYNAMIC_VALIDATION` 阶段。目标架构无法仿真或需要快速执行纯静态分析时可使用此选项。报告会将这些阶段标记为 `skipped_by_user`，与流水线失败明确区分。

## 🤖 模型服务辅助调查

模型服务集成为可选功能。确定性分析无需模型服务凭据即可运行；使用模型服务辅助的命令则需要配置模型 API。

FirmXplore 从环境变量或本地 `.env` 文件读取模型服务配置。必需的变量名如下：

```text
MODEL_PROVIDER
MODEL_NAME
MODEL_API_KEY
MODEL_BASE_URL
```

同时支持以下兼容别名：

```text
FWAGENT_MODEL_PROVIDER
FWAGENT_MODEL_NAME
FWAGENT_MODEL_API_KEY
FWAGENT_MODEL_BASE_URL
```

Git 和 Docker 构建均会忽略 `.env`。请勿将 API 密钥写入报告、提示词、提交或 Issue 文本。

`.env` 示例：

```text
MODEL_PROVIDER=openai-compatible
MODEL_NAME=gpt-4o-mini
MODEL_API_KEY=sk-xxxxxxxxxxxxxxxx
MODEL_BASE_URL=https://api.openai.com/v1
```

模型服务诊断：

```bash
firmxplore model-doctor --connect
firmxplore model-smoke
```

模型服务辅助的验证冒烟测试：

```bash
firmxplore agent-smoke my-analysis H-PROVIDER-SMOKE --workspace workspace
```

在真实任务上执行模型服务辅助调查：

```bash
firmxplore analyze firmware.bin --provider-backed
```

当前 v0.1 的模型服务验收验证的是**有界的模型服务辅助执行**。已验收的冒烟运行在控制器配置的步骤预算（`max_steps`）处终止，而非由模型自主判断收敛。

### 🔻 模型服务失败与降级模式

模型服务辅助调查循环具有明确边界和容错能力：

- **临时 API 错误**（连接重置、超时、HTTP 5xx）会触发指数退避重试。
- **持续 API 错误**会以 `stop_reason=model_error` 停止循环，并保留此前收集的全部证据、假设和工具调用。
- 环境中**缺少 Ghidra** 时，循环进入**降级模式**：仅使用字符串/符号级工具，并标记 `model_investigation.degraded=true`。

在第 5 轮最终化过程中，降级或中断的调查均为**非规范结果**。其输出位于 `report.model_hypotheses` 和 `report.model_evidence`，并明确标记为 `canonical=false`。

### 💰 模型用量与成本记录

每次模型服务 HTTP 调用都会记录到：

```text
workspace/<task-id>/web_model_usage.jsonl
```

每条记录包含 `ts`、`model`、`endpoint`、`prompt_tokens`、`completion_tokens`、`total_tokens` 和 `status`。该文件是 token 核算和成本审计的权威数据源，Web 控制台会在任务详情中展示同一份数据。

## 🛡️ 安全与证据模型

FirmXplore 采用保守策略：

- 仅分析本地且已获授权的固件。
- 不探测公共目标。
- 不向模型服务暴露任意 Shell、Docker、QEMU 或进程执行能力。
- 不生成漏洞利用载荷。
- 通过请求、工具调用、运行时间和环回网络控制限制动态验证范围。
- 跟踪证据来源和运行时观察状态。
- 将模拟、仿真、阻断和结论不明确的尝试排除在规范真实运行时确认之外。

解释规则：

- `SOURCE + SINK != VULNERABILITY`
- `CALL PATH != DATA FLOW`
- `REACHABLE != EXPLOITABLE`
- `HTTP 500 != VULNERABILITY`
- `RUNTIME RECONSTRUCTION != STOCK BOOT PARITY`

## 📄 报告

每个分析任务可以生成以下产物：

| **产物**                     | **路径**                                                  |
| :--------------------------- | :-------------------------------------------------------- |
| JSON 报告                    | `workspace/<task-id>/reports/report.json`                 |
| Markdown 报告                | `workspace/<task-id>/reports/report.md`                   |
| HTML 报告                    | `workspace/<task-id>/reports/report.html`                 |
| 报告清单                     | `workspace/<task-id>/reports/report_manifest.json`        |
| 流水线摘要                   | `workspace/<task-id>/pipeline_summary.json`               |
| 流水线阶段                   | `workspace/<task-id>/pipeline_stages.json`                |
| 提取记录                     | `workspace/<task-id>/artifacts/extraction.json`           |
| 规范根文件系统记录           | `workspace/<task-id>/artifacts/rootfs.json`               |
| Ghidra 摘要                  | `workspace/<task-id>/ghidra/analysis_summary.json`        |
| 攻击面                       | `workspace/<task-id>/surface/attack_surface_summary.json` |
| 污点分析摘要                 | `workspace/<task-id>/taint/summary.json`                  |
| 假设                         | `workspace/<task-id>/hypotheses/synthesis_analysis.json`  |
| 模型服务调查追踪             | `workspace/<task-id>/reports/investigation.json`          |
| 模型服务 token 用量          | `workspace/<task-id>/web_model_usage.jsonl`               |
| 动态证据                     | `workspace/<task-id>/dynamic/evidence/evidence.json`      |
| 发现                         | `workspace/<task-id>/findings/findings.json`              |

HTML 报告是本地离线产物，不是 Web UI。

## ✅ 已验证示例

### 示例 1：TP-Link SR20（ARM，真实动态验证 + 模型服务）

```text
tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin
```

| **指标**                 | **结果**                     |
| :----------------------- | :--------------------------- |
| 提取后端                 | Docker/binwalk               |
| RootFS 文件数            | 2255                         |
| ELF 二进制文件数         | 457                          |
| 架构                     | ARM 32 位小端                |
| 真实 Docker 化 Ghidra    | 20 / 20                      |
| Ghidra 回退              | 0                            |
| 运行时路径               | 选定的 FastCGI 集成路径      |
| 真实运行时观察           | 4                            |
| 最终发现                 | 0                            |

选定的 FastCGI 验证到达了应用，并针对未知 SOAP 操作观察到 HTTP 500 SOAP 错误。该响应是安全探测下的应用行为，不构成漏洞结论。FirmXplore 将 `Findings: 0` 解释为**没有根据规范证据提升漏洞结论**，而非运行失败。

### 示例 2：TP-Link TEW-751DR（MIPS 大端，静态分析 + 模型服务，不执行动态验证）

```text
TEW751DR_FW103B03.bin
```

| **指标**                 | **结果**                       |
| :----------------------- | :----------------------------- |
| 提取后端                 | Docker/binwalk                 |
| RootFS 文件数            | 1527                           |
| ELF 二进制文件数         | 121                            |
| 架构                     | MIPS 大端                      |
| 真实 Docker 化 Ghidra    | 12 / 12                        |
| 攻击面条目               | 27                             |
| 污点源                   | 27                             |
| 污点汇                   | 56                             |
| 候选发现                 | 14                             |
| 运行时验证               | 已跳过（`--no-dynamic`）       |

全部 14 条发现均为 `status=candidate`，置信度为 0.35–0.42，并分别包含明确的 `missing_evidence` 列表（参数映射、运行时汇观察、净化逻辑行为、参数级源到汇映射）。在缺少运行时或参数级证据时，FirmXplore 不会将候选项提升为规范发现。

## 🧪 v0.1 验收状态

当前状态：

`FIRMXPLORE V0.1 REAL DYNAMIC + REAL PROVIDER ACCEPTED / MULTI-FIRMWARE ACCEPTANCE PARTIAL`

| **能力**                                           | **状态** |
| :------------------------------------------------- | :------- |
| 全新提取                                           | 通过     |
| 规范 RootFS                                        | 通过     |
| 真实 Docker 化 Ghidra                              | 通过     |
| 跨组件关联                                         | 通过     |
| 静态攻击面发现                                     | 通过     |
| 污点源发现                                         | 通过     |
| 安全的真实动态运行时                               | 通过     |
| 规范运行时证据                                     | 通过     |
| 模型服务辅助智能体                                 | 通过     |
| 模型服务降级模式                                   | 通过     |
| 结构化输出                                         | 通过     |
| 受控工具调用                                       | 通过     |
| token 用量跟踪                                     | 通过     |
| ARM 真实固件                                       | 通过     |
| MIPS 架构夹具                                      | 通过     |
| MIPS 真实固件（静态）                              | 通过     |
| 不支持输入的处理                                   | 通过     |
| 其他真实固件的提取/静态报告                        | 部分完成 |
| 多固件真实验收                                     | 部分完成 |

要达到完整候选发布（RC）兼容性要求，仍需在第二个不同的、已获授权的真实固件镜像上完成真实 Ghidra、运行时和模型服务验收。因此，当前文档不会将 FirmXplore v0.1 描述为已达到 RC 就绪状态。

## 🧩 已验证样本

| **样本类别**                    | **状态**     | **说明**                                                                                                       |
| :------------------------------ | :----------- | :------------------------------------------------------------------------------------------------------------- |
| TP-Link SR20 真实固件           | 通过         | 真实提取、Ghidra、选定动态运行时和模型服务验收                                                                 |
| TP-Link TEW-751DR 真实固件      | 通过（静态） | MIPS 大端、真实 Ghidra、静态攻击面、候选发现、`--no-dynamic`                                                   |
| D-Link DIR-815 真实固件         | 部分完成     | 通过 `sasquatch` 提取旧版 SquashFS/LZMA，生成 MIPS 小端清单和报告；真实 Ghidra/运行时验证部分完成              |
| Huawei HG532e 真实固件          | 部分完成     | 通过 `sasquatch` 提取大端 SquashFS/LZMA，生成 MIPS 大端清单和报告；真实 Ghidra/运行时验证部分完成              |
| MIPS 架构夹具                   | 通过         | 仅用于夹具集成覆盖                                                                                             |
| 不透明且不支持的样本            | 通过         | 能够优雅地部分处理，不会崩溃                                                                                   |

## ⚠️ 已知限制

1. 完整的真实动态/模型服务验收目前只覆盖少量不同的真实固件镜像；其他真实固件镜像仅有提取/静态报告。
2. 动态验证已在选定 FastCGI 路径上完成演示，尚未覆盖每个固件服务。
3. 运行时修复只能证明重建环境中的可达性，不能证明与厂商原始启动序列一致。
4. 源—汇关联以证据为导向，不代表漏洞已经得到确认。
5. 模型服务辅助执行受确定性控制器预算约束。
6. 无法保证每个镜像都能完成全固件仿真。
7. 静态攻击面发现目前覆盖启动脚本、服务配置、Web 路由布局和 Ghidra 导入的网络调用；固件特有的服务管理器可能需要额外启发式规则。

## 🧰 开发与测试

运行完整测试套件：

```bash
python -m unittest discover -v
```

已配置本地工作区可运行由环境变量控制的真实动态/模型服务验收测试：

```powershell
$env:FIRMXPLORE_RUN_REAL_DYNAMIC_TESTS='1'
$env:FIRMXPLORE_RUN_REAL_PROVIDER_TESTS='1'
python -m unittest tests.integration.test_v01_real_dynamic_provider_acceptance -v
```

构建默认的容器化 Ghidra/提取工作进程：

```bash
docker build -t firmxplore:latest .
```

容器包含 `binwalk`、`unblob`、`unsquashfs` 和 `sasquatch`，因此默认 Docker 提取路径能够恢复旧版 SquashFS 3.x/4.x LZMA 固件镜像。系统会先解包厂商 ZIP 发布包等归档封装；如果封装本身不含 Linux 根文件系统，则通过 Docker 提取路径重试其中的嵌入式固件镜像。

`firmxplore:latest` 和 `firmxplore-dynamic:latest` 是为复现元数据而保留的内部实现镜像名；FirmXplore 是产品名称。

## 📁 项目结构

```text
FirmXplore/
  assets/
    architecture.png
    workflow.png
    Falcons.png
    CTRA.png
  fwagent/        # 内部 Python 包
  config/         # Ghidra 与动态验证配置
  ghidra_scripts/ # 容器化 Ghidra 导出辅助脚本
  tests/          # 单元测试与集成测试
  workspace/      # 生成的任务工作区，Git 忽略
  reports/        # 本地生成的报告，Git 忽略
```

## 🤝 团队与支持

<p align="left">
  <img src="./assets/sysresear-lab.png" height="30" style="vertical-align: middle;" alt="Falcons Lab"/>
  <strong style="margin-left: 8px;">Sysresear Lab</strong>
</p>

<table>
  <tr>
    <td align="center" width="90">
      <a href="https://github.com/zer0ptr">
        <img src="https://avatars.githubusercontent.com/u/196273893?v=4" width="70px" alt="Hailin Zheng"/>
      </a><br/>
      <a href="mailto:iszhenghailin@gmail.com"><sub><b>Hailin Zheng</b></sub></a>
    </td>
    <td align="center" width="90">
      <a href="https://github.com/xiaohen711">
        <img src="https://avatars.githubusercontent.com/u/204820747?v=4 width="70px" alt="Hailin Zheng"/>
      </a><br/>
      <a href="mailto:iszhenghailin@gmail.com"><sub><b>Shibing Deng</b></sub></a>
    </td>
    <td align="center" width="90">
      <a href="https://github.com/colorfulbird3">
        <img src="https://avatars.githubusercontent.com/u/221922291?v=4" width="70px" alt="Qingyi Huang"/>
      </a><br/>
      <a href="mailto:a1396228851@outlook.com"><sub><b>Qingyi Huang</b></sub></a>
    </td>
    <td align="center" width="90">
      <a href="https://github.com/Fa2maZ">
        <img src="https://avatars.githubusercontent.com/u/284943533?v=4" width="70px" alt="Guandong Li"/>
      </a><br/>
      <sub><b>Guandong Li</b></sub>
    </td>
  </tr>
</table>

## 📜 许可证

本项目在 `pyproject.toml` 中配置为 MIT 许可证。
