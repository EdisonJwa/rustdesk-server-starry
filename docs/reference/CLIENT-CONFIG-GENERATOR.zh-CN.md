# 客户端配置生成器

[English](CLIENT-CONFIG-GENERATOR.md) | **简体中文**

`starry-client-config` 直接从运行中服务器的密钥材料渲染 RustDesk 客户端所需的
三个事实——ID 服务器、中继服务器与服务器公钥，让运维不再凭记忆粘贴已轮换的
密钥。它是 Pro 自定义客户端生成器的轻量对应物：只分发配置，不构建客户端。

## 用法

```sh
starry-client-config \
  --data-dir /var/lib/rustdesk-server-starry/hbbs \
  --id-server id.example.test:21116 \
  --relay-server relay.example.test:21117 \
  --group contractors
```

- `--data-dir` 指向 HBBS 状态目录；只读取 `id_ed25519.pub`。绝不触碰私有材料。
- `--format text`（默认）一次性渲染所有形态；`--format json` 只输出机器可读
  文档。
- **导入字符串**使用 RustDesk 线格式：JSON 载荷
  \{"host", "relay", "api", "key"\} 经 base64 编码后整串反转（开头 `==` 属
  正常），使扫描器无法识别为 base64。客户端反转、解码后解析。
- `--group NAME` 在输出中标注设备所属的策略组。服务器策略文档必须匹配设备
  ID，组策略才会生效；该标注只是提醒，不构成强制。
- `--out FILE` 把结果写入文件而非 stdout（便于配合 `--format json` 脚本化）。

## 诚实边界

本工具绝不签发访问 token：连接 token 属于运维方的身份提供者——这正是 JWT
连接认证设计的全部意义。
