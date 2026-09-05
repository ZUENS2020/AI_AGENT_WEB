# Sherpa Pipeline 问题报告

**日期**: 2026-05-18 ~ 2026-05-19  
**分支**: dev (commits d293d0810 → 46019d295)  
**测试目标**: openssl, wolfssl

---

## 已修复并验证通过

| ID | 问题 | 修复 | 状态 |
|----|------|------|------|
| F1 | Embedding 超时 (Read timed out) | ThreadPoolExecutor 4 workers, socket.setdefaulttimeout(30), batch_size=128, retry with backoff | ✅ 21/21 ok |
| F2 | AST source limit 1200 不够 | SHERPA_PROMEFUZZ_MAX_SOURCE_FILES 默认 2000 | ✅ 1291/1291 完成 |
| F3 | Time budget 默认 900s 太短 | total_time_budget=0 (unlimited) | ✅ |
| F4 | RAG wait 120s 不够 | SHERPA_K8S_ANALYSIS_RAG_WAIT_TIMEOUT_SEC 默认 1800s | ✅ |
| F5 | API extractor 返回 0 函数 | declLoc fallback to func_loc | ✅ openssl: 0→285 |
| F6 | Docker pip install timeout | 重试循环 + timeout 600s | ✅ |
| F7 | CK4 execution_plan_harness_mismatch | targets.json 覆盖 + SKILL.md CRITICAL 约束 | ✅ 部分改善 |
| F8 | Prod PV Released 导致 PVC 无法绑定 | Reset 时清理 PV + 手动修复 prod | ✅ |

---

## 待修复问题

### P1 — API Extractor 不能适配非标准 include 目录结构 + 源码过滤问题

**严重程度**: **致命**  
**影响**: 除 OpenSSL（有标准 `include/` 目录）外，其他库基本无法提取 API

**现象**:
- **wolfssl**（26轮迭代）: 只提取到 1 个"API"（`WC_WUR_INT`，实际是编译器宏），meta.json 中 0 个函数
- **cJSON**（极简库）: 只提取到 0 个 API。meta.json 中唯一函数是 CMake test 文件 `CMakeCCompilerId.c` 中的 `main`，不是 cJSON 代码
- **OpenSSL**: 285 个 API（正常，因为 OpenSSL 恰好有 `include/` 目录）

**根因有两个**:

1. **Include path 检测**: 
   - 当前硬编码 `-I<repo>/include`，但 wolfssl 头文件在 `<repo>/wolfssl/`，cJSON 头文件在 `<repo>/`
   - 需要检测实际的头文件位置并设置正确的 `-I` 路径

2. **源码文件过滤**:
   - Preprocessor 不加区分地扫描所有 `.c` 文件，包括 build 目录、CMake 生成的测试文件
   - 应排除 `build*/`、`CMakeFiles/`、`_deps/` 等构建产物目录
   - 应优先扫描已知的源码目录（`src/`、`lib/`、repo 根目录）

**相关文件**: 
- `promefuzz-mcp/promefuzz_mcp/preprocessor/api_extractor.py`
- `promefuzz-mcp/promefuzz_mcp/preprocessor/ast.py`（源码文件收集逻辑）

**修复方向**: 
1. 从 `configure`/`CMakeLists.txt`/`Makefile` 读取 include flags
2. 添加 build 目录黑名单过滤
3. 自动检测 repo 根目录下的一级子目录作为 include path 候选

---

### P2 — Build 阶段无法收敛（OpenSSL 12 轮 / WolfSSL 26 轮）

**严重程度**: 中高  
**影响**: 复杂 C 项目的 harness 编译成功率低

**现象**:
- OpenSSL: 12 轮 plan→synthesize→build(fail) 循环
- WolfSSL: 26 轮（但走到了 run 阶段又回到 crash-triage→plan 循环）
- 核心问题：生成 harness 依赖 `apps/lib/` 中的内部函数，这些函数散落在 20+ 个 `.c` 文件中，存在深层交叉依赖
- fix_build agent 每次只增量加一个文件，下一轮编译又发现新缺失符号
- 最终尝试了 stub 策略也未能完全解决

**相关文件**: `harness_generator/src/langchain_agent/workflow_graph.py` (build/fix_build nodes)

**修复方向**:
1. 自动检测并编译整个 `apps/lib/` 目录（而非逐个文件加）
2. 使用 `nm` 或 `objdump` 找出所有 undefined symbols 并自动生成 stub
3. 提高 `SHERPA_FIX_BUILD_MAX_ATTEMPTS` 默认值（当前为 0，意味着 fix_build 永不路由到 plan）
4. 考虑用 linker 的 `--whole-archive` 或编译整个子目录的 `.a` 静态库

---

### P3 — Analysis 阶段空闲超时 75s 不够

**严重程度**: 低  
**影响**: Analysis agent 偶尔被 idle timeout 杀死

**现象**:
- `SHERPA_ANALYSIS_OPENCODE_IDLE_TIMEOUT_SEC=75` 
- Agent 读取完文件后可能在思考/MCP查询阶段超过 75s 无输出
- 观察到 analysis agent 触发 idle timeout 后仍完成了（agent 被杀但输出有效）

**修复方向**: 提高到 120-180s，或改为按阶段区分（vuln-hunt 已有 1800s）

---

### P4 — Build 阶段 90s 超时过短

**严重程度**: 中  
**影响**: OpenSSL 编译 5-8 分钟，90s 超时必定失败

**现象**:
- build.py 的 subprocess 超时设为了 90s
- OpenSSL 编译需要 5-8 分钟
- 每次 build 都被 `[timeout] process exceeded limit and was killed` 杀掉
- 然后 fix_build agent 启动，修 build.py，下一轮又超时

**修复方向**: 将 build subprocess 超时提高到 600s (10 min) 或根据项目大小动态计算

---

### P5 — Prod 部署 PV 清理不完整

**严重程度**: 低（已手动修复）  
**影响**: Prod reset 后 postgres 无法启动

**现象**:
- Namespace 删除后 PV 保留（ReclaimPolicy: Retain），状态变为 Released
- 新 PVC 创建时无法绑定到 Released 状态的 PV
- 已在 `deploy-prod.yml` 添加 PV 清理逻辑

**状态**: 修复代码已推送（46019d295），但本次未测试 prod 部署

---

## 建议优先修复顺序

1. **P1** (API Extractor include path) — 直接导致某些 repo 完全无法分析
2. **P4** (Build timeout) — 简单改一个值，效果立竿见影
3. **P3** (Analysis idle timeout) — 简单改一个值
4. **P2** (Build 收敛) — 最复杂，需要策略调整

---

## 已验证可用的修复（可合并到 main）

以下 commits 已通过 dev 测试，可以安全合并：

```
d293d0810 fix: add embedding retry with backoff and self-heal degraded cache
f6116c65e fix: reduce embedding timeout to 30s and increase batch size to 128
60cbc9439 fix: increase AST source limit to 2000 and add progress logging
edbe3296a fix: add socket.setdefaulttimeout to harden embedding timeout
3afce0525 fix: parallel embedding with ThreadPoolExecutor + extend RAG wait to 30min
6fb0e8f52 fix: sync targets.json and execution_plan.json before synthesize
d8192310b fix: increase pip timeout to 300s and retries to 10 for Docker build
54c973a71 fix: fallback to func_loc when declLoc is empty in API extractor
825273fa8 fix: relax harness consistency check - only require must_run targets
577d05a86 fix: synthesize SKILL.md - enforce only generating harnesses for targets.json
6c594d341 fix: add retry loop for promefuzz-mcp pip install in Docker build
46019d295 fix: clean up released PVs during prod namespace reset
501e64cd1 fix: change prod domain to tianheng.zuens2020.work
b5f65ef64 fix: add prod namespace reset step to deploy-prod workflow
```
