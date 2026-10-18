# FirmXplore Web

为 FirmXplore（fwagent）固件安全分析 CLI 提供的 Web 界面：上传固件、后台执行分析、
SSE 实时进度、报告查看（JSON / Markdown / HTML 下载）与产物浏览。

```
web/
├── server/                  # FastAPI 后端
│   ├── main.py              # 全部 API 路由 + 前端静态托管
│   ├── tasks.py             # fwagent 适配层：后台执行、进度轮询、SSE 事件分发
│   ├── config.py            # 运行时配置（环境变量）
│   ├── database.py          # SQLAlchemy 引擎/会话
│   ├── models.py            # tasks / app_config 表
│   ├── schemas.py           # Pydantic 请求/响应模型
│   ├── security.py          # API Key 的 Fernet 加密存储
│   └── requirements.txt
├── frontend/                # React 18 + TypeScript + Vite + Tailwind
│   └── src/
│       ├── api/client.ts    # 后端 API 封装
│       ├── hooks/           # useTasks / useTaskStream(SSE) / useConfig
│       ├── components/      # Layout、LogConsole、FindingsView、ui/（shadcn 风格）
│       └── pages/           # TasksPage / NewAnalysisPage / TaskDetailPage / SettingsPage
├── Dockerfile.web
└── docker-compose.web.yml
```

## 本地开发

后端默认拒绝匿名访问。启动前设置 `FIRMXPLORE_WEB_USERS` 为 JSON 对象，键为
1–32 位字母/数字/下划线/连字符的身份名，值为该身份独立生成的至少 32 字符随机 ASCII token。
没有内置默认 token；不要在 URL 中传 token。浏览器访问后端首页时使用 HTTP Basic 登录
（身份名 / token），API 客户端也可以使用 `Authorization: Bearer <token>`。
先访问后端首页完成浏览器认证，再使用 Vite 开发前端；跨站修改请求会被拒绝。
本地后端监听 `127.0.0.1`，Compose 只向宿主 loopback 发布端口；远程使用必须由部署者配置 HTTPS。

每个身份只能管理自己新建的任务与模型配置。旧全局配置不会自动分配给新身份；需重新配置。
旧任务仅作 additive schema 兼容，`owner_id=NULL` 的旧行保持隔离，不返回、续跑、下载或自动清理；
含旧快照字段的任务即使人为补 owner 仍拒绝访问。不会自动改写旧快照或读取旧 Key。
如需迁移，应先单独备份并安排受控离线迁移；本阶段不提供自动认领/解密旧数据的接口。

新任务快照采用公开字段白名单；每任务凭据保存在独立 `task_credentials` 加密表，
仅在执行前按 owner 读取，并通过 stdin 内存管道传给 runner，不写 spec、命令参数或产物。
下载仅提供允许的公开产物；输入、环境、配置、spec、日志和任意任务目录文件不再直接下载。
原数据库/密钥文件仍须由服务账户保护；本阶段不清除旧数据库中的明文副本，旧凭据轮换需另行处理。

```bash
# 1. 后端（仓库根目录执行；端口 8000）
pip install -r web/server/requirements.txt
python -m uvicorn web.server.main:app --reload --port 8000

# 2. 前端（Vite 开发服务器，代理 /api 到 8000）
cd web/frontend
npm install
npm run dev            # http://localhost:5173
```

生产部署直接由 FastAPI 托管 `web/frontend/dist`（先 `npm run build`），
访问 http://localhost:8000 即可，无需单独起前端服务。

## Docker 部署

```bash
docker build -t fwagent-round2:latest .      # 先构建 CLI 分析环境镜像（主 Dockerfile）
docker compose -f web/docker-compose.web.yml up --build
```

## 关键设计

- **fwagent 适配点**：分析在独立子进程中运行（`web/server/runner.py`，通过
  `python -m web.server.runner <spec.json>` 启动），子进程内调用
  `AnalysisPipelineController(workspace).analyze(firmware, task_id=..., ...)`；
  配置通过 `MODEL_PROVIDER` 等环境变量注入（fwagent/model/config.py 定义的键名）。
  子进程化带来三个能力：**暂停/恢复**（终止进程 + `analyze(resume=True)` 续跑）、
  **日志采集**（stdout/stderr 重定向到 `web_console.log`）、故障隔离。
- **实时日志**：watcher 线程每 2s 采集 `web_console.log`（fwagent 的 [N/15] 进度输出）
  和 `logs/commands.jsonl`（fwagent CommandRunner 的命令记录），随 SSE 推送。
- **拓扑图**：`GET /api/tasks/{id}/graph` 返回 `correlation/component_graph.json`
  （fwagent ComponentGraphBuilder 产物）中的组件节点与关联边，前端用内置的
  力导向 SVG 布局渲染（无第三方图表依赖）。
- **API Key**：Fernet 加密存入 SQLite（密钥来自 `WEB_SECRET_KEY` 环境变量，
  或自动生成到 `web/data/.secret_key`）。任何接口不回传明文，前端只见 `api_key_set` 布尔位。
- **确定性模式**：勾选后不注入任何凭证，`MODEL_PROVIDER=deterministic`，
  fwagent 走确定性调查/验证路径，完全离线可用。
- **SSE**：`EventHub` 为每个任务维护 `asyncio.Queue` 订阅者集合；watcher 线程通过
  `loop.call_soon_threadsafe` 投递事件；SSE 端点 15 秒无事件发送 keep-alive 注释。
- **并发**：`WEB_MAX_CONCURRENT_TASKS`（默认 1）个分析任务并行，多余的上传进入排队
  （pending 状态）；生产部署保持 `--workers 1`（进程内状态）。
- **清理**：后台协程每小时删除超过 `WEB_RETENTION_DAYS`（默认 7 天）的终态任务的
  DB 记录、上传文件与工作区目录；运行中的任务需先暂停再删除；
  服务重启时将遗留的 running/pending 任务标记为失败。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `WEB_WORKSPACE_ROOT` | `<repo>/workspace` | fwagent 分析工作区 |
| `WEB_UPLOAD_ROOT` | `<repo>/web/data/uploads` | 固件上传暂存 |
| `WEB_DATABASE_URL` | `sqlite:///<repo>/web/data/firmxplore.db` | 任务数据库 |
| `WEB_SECRET_KEY` | 自动生成 | API Key 加密密钥（生产必设） |
| `WEB_CORS_ORIGINS` | `http://localhost:5173,...` | 允许的跨域来源 |
| `WEB_MAX_UPLOAD_MB` | `1024` | 上传大小限制 |
| `WEB_MAX_CONCURRENT_TASKS` | `1` | 并行分析任务数 |
| `WEB_RETENTION_DAYS` | `7` | 任务保留天数（0 不清理） |

## API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/config` | 保存 provider 配置（api_key=null 保留旧值） |
| GET | `/api/config` | 配置状态（不返回 Key 明文） |
| POST | `/api/analyze` | multipart 上传固件并启动分析，返回 `{task_id}` |
| GET | `/api/tasks?status=` | 任务列表 |
| GET / DELETE | `/api/tasks/{id}` | 任务详情 / 删除（运行中不可删） |
| GET | `/api/tasks/{id}/stream` | SSE 实时状态推送（event: status） |
| POST | `/api/tasks/{id}/stop` | 暂停任务（终止子进程，保留工作区） |
| POST | `/api/tasks/{id}/resume` | 恢复已暂停的任务（fwagent resume） |
| GET | `/api/tasks/{id}/graph` | 组件关联拓扑图（correlation 产物） |
| GET | `/api/tasks/{id}/report?format=json\|md\|html` | 报告（html 为附件下载） |
| GET | `/api/tasks/{id}/artifacts` | 产物列表 |
| GET | `/api/tasks/{id}/artifacts/{path}` | 下载产物（防目录穿越） |

### Temporary firmware execution lock

QEMU user-mode boot, smoke, trace, service/application start and FastCGI runtime probes now return `UNISOLATED_FIRMWARE_EXECUTION_BLOCKED` before execution or runtime preparation. `scripts/validate_dynamic_hardening.py` returns the same block without rewriting existing diagnostics. There is no environment/configuration bypass. Static inspection, dependency analysis and parsing saved traces remain available. Existing runtime evidence is historical; this lock does not validate it or implement a sandbox. Automatic fallback and direct whole-system/FirmAE boot entry points are blocked by the same lock until a separate isolation review.
