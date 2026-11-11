// Package i18n provides the built-in CLI messages. zh/en are complete; fr, fa,
// ru and ko are declared for CLI compatibility with the Bash manager but have
// no Go catalog yet, so they explicitly fall back to English instead of
// silently pretending to be translated.
package i18n

import "fmt"

var supported = map[string]bool{"zh": true, "en": true, "fr": true, "fa": true, "ru": true, "ko": true}

// complete marks languages with a full Go catalog.
var complete = map[string]bool{"zh": true, "en": true}

// Supported reports whether lang is one of the six accepted language codes.
func Supported(lang string) bool { return supported[lang] }

// Complete reports whether lang has a Go catalog of its own.
func Complete(lang string) bool { return complete[lang] }

// FallbackNotice explains the English fallback; it returns "" for a complete
// or unknown language so callers can print it unconditionally.
func FallbackNotice(lang string) string {
	if !Supported(lang) || Complete(lang) {
		return ""
	}
	return T("en", "lang_incomplete", lang)
}

var zh = map[string]string{
	"help": `Idleleo Xray 管理器（%s）
用法: idleleo [--root PATH] [--lang zh|en|fr|fa|ru|ko] <命令>

命令:
  version              显示版本
  status               只读状态
  show                 只读运行与分享信息
  config inspect       只读结构化配置视图
  change set-inbound-port --sandbox PATH --port N --validator PATH
                       在一次性沙箱或真实根上修改入站端口
                       （真实根用 --sandbox / 并加 --service 与 --container）
  change recover       收敛被硬中断的变更事务（回滚或补记 COMMITTED）
  xray generate        生成运行配置（reality/tls/ws/grpc/xhttp、relay、balance）
  xray share           为现有配置输出分享链接与 Clash 配置
  xray relay           生成指向后端的 nginx 中转配置
  xray user list|add|remove
                       列出现有用户，或增删用户（增删需沙箱或真实根门禁）
  xray install --binary PATH
                       用本地二进制安装 Xray 并接管根目录
  xray uninstall|recover
                       卸载托管文件 / 收敛未完成的安装
  xray cert issue|renew
                       ACME v2 证书签发与续期（默认 LE staging；生产需 --production 或 IDLELEO_ACME_DIRECTORY）
  bridge audit|prepare|validate|activate|deactivate|recover|status
                       旧 Bash 安装的审计、预检、切换、回退与恢复
  metadata import|export [--from install_config.json] [--out FILE]
                       从旧配置派生唯一元数据 / 导出并校验运行时摘要
  schedule install|remove|run|status|alert
                       Go 原生定时任务（到期前 30 天自动续签；alert 供 OnFailure 使用）
  update status|check|apply|configure --manifest-url URL
                       Go 发布通道自更新（校验 manifest/SHA256/ELF/健康检查）
  stats [--json]       只读查询 Xray 统计（reset=false）
  service status|start|stop|restart|reload|logs [--unit xray|nginx]
                       服务类操作（仅真实 systemd）
  tcp status|plan|apply|rollback --profile bbr-fq --confirm
                       Go 原生 TCP 配置（仅管理 /etc/sysctl.d/90-idleleo-tcp.conf）
  speedtest [--json] [--server URL] [--bytes N] [--samples N] [--timeout 10s]
                       下行测速（本机实现，不下载执行第三方脚本）
  rill status          只读 Rill 交接状态
  recover              收敛未完成的 xray install
  help                 显示本帮助

语言: zh、en 已完整；fr、fa、ru、ko 暂时回退到英文。
`,
	"version":          "idleleo %s (go)\n",
	"usage":            "命令或参数无效\n",
	"lang_incomplete":  "提示：%s 词条尚未完成，本次输出已回退英文（--lang en 可关闭该提示）\n",
	"not_installed":    "未安装：缺少 manager metadata；只读命令不会创建任何文件\n",
	"corrupt":          "配置损坏：%s\n",
	"schema_high":      "metadata schema 过新：%s\n",
	"unsupported":      "不支持的模式：%s\n",
	"permission":       "权限不足：%s\n",
	"drift":            "检测到外部变更：%s\n",
	"locked":           "已有一个变更事务持有锁\n",
	"validation":       "候选配置未通过校验（退出码 %d）：%s\n",
	"service_failed":   "服务应用失败（退出码 %d），已回滚：%s\n",
	"recovery":         "回滚失败，需要人工恢复：%s\n",
	"io_error":         "文件操作失败：%s\n",
	"not_implemented":  "该功能尚未实现（退出码 11）\n",
	"sandbox_required": "变更只允许有标记的一次性沙箱\n",
	"root_required":    "该命令需要 root\n",
	"no_tty":           "无 TTY：不进入交互菜单\n",
}

var en = map[string]string{
	"help": `Idleleo Xray manager %s
Usage: idleleo [--root PATH] [--lang zh|en|fr|fa|ru|ko] <command>

Commands:
  version              print version
  status               read-only status
  show                 read-only runtime and share information
  config inspect       read-only structured config view
  change set-inbound-port --sandbox PATH --port N --validator PATH
                       change one inbound port in a sandbox or on the real root
                       (real root: --sandbox / plus --service and --container)
  change recover       converge a change interrupted by a hard kill
  xray generate        generate a runtime config (reality/tls/ws/grpc/xhttp, relay, balance)
  xray share           print share URI and Clash YAML for an existing config
  xray relay           generate the nginx relay conf for one backend
  xray user list|add|remove
                       list users, or add/remove one (add/remove need a sandbox or the real-root gate)
  xray install --binary PATH
                       install Xray from a local binary and take over the root
  xray uninstall|recover
                       remove managed files / converge a half-finished install
  xray cert issue|renew
                       ACME v2 issuance and renewal (defaults to LE staging; production needs --production or IDLELEO_ACME_DIRECTORY)
  bridge audit|prepare|validate|activate|deactivate|recover|status
                       audit, pre-flight, switch, hand-back and recovery for legacy Bash installs
  metadata import|export [--from install_config.json] [--out FILE]
                       derive the single metadata record / export with runtime digest check
  schedule install|remove|run|status|alert
                       native Go jobs (auto-renew inside 30 days; alert backs OnFailure)
  update status|check|apply|configure --manifest-url URL
                       Go release channel self-update (manifest/SHA256/ELF/health checks)
  stats [--json]       read-only Xray stats query (reset=false)
  service status|start|stop|restart|reload|logs [--unit xray|nginx]
                       service-class operations (real systemd only)
  tcp status|plan|apply|rollback --profile bbr-fq --confirm
                       native TCP profile (only /etc/sysctl.d/90-idleleo-tcp.conf)
  speedtest [--json] [--server URL] [--bytes N] [--samples N] [--timeout 10s]
                       downstream throughput (local, no third-party script)
  rill status          read-only Rill handover state
  recover              converge a half-finished xray install
  help                 show this help

Languages: zh and en are complete; fr, fa, ru and ko fall back to English for now.
`,
	"version":          "idleleo %s (go)\n",
	"usage":            "invalid command or arguments\n",
	"lang_incomplete":  "note: %s messages are not translated yet, falling back to English (use --lang en to silence this)\n",
	"not_installed":    "not installed: manager metadata is missing; read-only commands create nothing\n",
	"corrupt":          "corrupt state: %s\n",
	"schema_high":      "metadata schema is too new: %s\n",
	"unsupported":      "unsupported mode: %s\n",
	"permission":       "permission denied: %s\n",
	"drift":            "external change detected: %s\n",
	"locked":           "another change transaction holds the lock\n",
	"validation":       "candidate rejected by validator (exit %d): %s\n",
	"service_failed":   "service apply failed (exit %d), rolled back: %s\n",
	"recovery":         "rollback failed; manual recovery required: %s\n",
	"io_error":         "file operation failed: %s\n",
	"not_implemented":  "not implemented yet (exit 11)\n",
	"sandbox_required": "mutations require a marked disposable sandbox\n",
	"root_required":    "this command requires root\n",
	"no_tty":           "no TTY: interactive menu not entered\n",
}

// T returns a localized message, falling back to English.
func T(lang, key string, args ...any) string {
	table := en
	if lang == "zh" {
		table = zh
	}
	msg, ok := table[key]
	if !ok {
		msg = key
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}
