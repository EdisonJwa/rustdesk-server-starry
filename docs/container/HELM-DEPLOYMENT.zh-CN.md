# Kubernetes 部署（Helm）

[English](HELM-DEPLOYMENT.md) | **简体中文**

[`deploy/helm/rustdesk-server-starry`](../../deploy/helm/rustdesk-server-starry)
下的 chart 运行 Starry 数据面：HBBS 负责信令，HBBR 负责中继流量。

## 形态

一次发布运行**一个 HBBS 与一个 HBBR，两者同 Pod 并共享宿主网络**，因为二者都
绑定 RustDesk 的固定端口（21115、21116 tcp+udp、21117）。同一节点上的第二个
副本会端口冲突，因此横向扩展靠增加节点、每节点一次发布，而不是提高
`replicas`。

两个容器都把状态放在 PersistentVolumeClaim 上：HBBS 拥有 `id_ed25519`、其公钥、
数据库与 Starry 配置文档；HBBR 拥有 `RELAY_DATA_DIR` 下的 Starry 中继身份布局。

## 安装

```sh
helm install starry deploy/helm/rustdesk-server-starry \
  --namespace rustdesk --create-namespace \
  --set image.digest=sha256:<release-digest>
```

生产环境请钉住 `image.digest`：标签必须指向中心实际运行的同一产物，而摘要让这
一点可验证。

### 启用 Starry 特性

在 `hbbs.config` 放入配置文档之前，Starry 保持关闭：

```sh
helm upgrade starry deploy/helm/rustdesk-server-starry \
  --reuse-values --set-file hbbs.config=config/config.geo-basic.yaml
```

Schema 参考在 [`docs/reference`](../reference)，随附示例在 [`config/`](../../config)。

### 监督与指标

HBBR 提供只读运维端点，默认在回环上开启：

- `hbbr.operations.listen`（默认 `127.0.0.1:21120`）是监听地址；
- 存活与就绪探针都使用 `/healthz`，这也是此处默认开启该端点的原因——清空该
  设置即可回退到 TCP 探针；
- `hbbr.serviceMonitor.enabled=true` 会额外创建 `ServiceMonitor` 与 headless
  `Service`，让 Prometheus Operator 每隔 `hbbr.serviceMonitor.interval` 抓取
  `/metrics`。这需要该 Operator 的 CRD。

请把监听保持在回环上。除非设置 `hbbr.operations.allowPublic=true`，它会拒绝公网
地址，因为负载内容描述了容量与准入压力；需要公网抓取时应经由自带访问控制的
代理转发。

`/metrics` 报告的是一组与认证遥测一致的数字：活跃与容量会话数、活跃与容量
带宽、负载基点、待配对数量、运行时长，以及准入拒绝、探测结果与遥测认证失败
计数。

## 卷属主

若镜像不以 root 运行，需要把 `securityContext.volumeOwner.uid` 与
`volumeOwner.gid` 设为运行用户，因为 `prepare-state` init 容器会在任一服务器
写入密钥材料之前，对两个 PVC 应用该属主。

## 升级与回滚

刻意使用 `Recreate`：两个 Pod 无法占用同一组宿主端口。因此升级期间该节点的
RustDesk 服务会短暂不可用，繁忙节点升级前应先通过 Starry draining 文件摘除
流量。

用 `helm rollback` 回滚。若回滚同时改变 Starry schema，需要按
[`升级与回滚`](https://github.com/q1ngyang/rustdesk-server-starry/wiki/ZH-CN-Upgrade-and-Rollback)
所述执行降级导出。

## 本仓库中的验证

`helm lint` 通过，且渲染出的所有对象都用 `kubeconform -strict` 对照上游
Kubernetes schema 校验通过。发布工作流会重新执行 `helm lint`，并断言渲染出的
对象数量、两个 PVC、运维端点变量与可选的 `ServiceMonitor`。
