// Package i18n provides built-in Phase 01 messages. zh/en are complete;
// fr/fa/ru/ko intentionally fall back to English until the Phase 02 catalogs
// are generated from the existing i18n/languages resources.
package i18n

import "fmt"

var supported = map[string]bool{"zh": true, "en": true, "fr": true, "fa": true, "ru": true, "ko": true}

// Supported reports whether lang is one of the six shipped languages.
func Supported(lang string) bool { return supported[lang] }

var zh = map[string]string{
	"help": `Idleleo Xray 管理器（Phase 01 候选）
用法: idleleo [--root PATH] [--lang zh|en|fr|fa|ru|ko] <命令>

命令:
  version              显示版本
  status               只读状态
  show                 只读运行与分享信息
  config inspect       只读结构化配置视图
  change set-inbound-port --sandbox PATH --port N --validator PATH
                       在一次性沙箱内修改入站端口（Phase 01 演示）
  bridge audit|prepare|validate|activate|recover|status
                       旧 Bash 安装的审计、预检、切换与恢复
  schedule install|remove|run|status
                       Go 原生定时任务（接管旧 cron 的更新/证书/GeoData/统计）
  stats                未实现（退出码 11）
  help                 显示本帮助
`,
	"version":          "idleleo %s (go)\n",
	"usage":            "命令或参数无效\n",
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
	"not_implemented":  "该功能在 Phase 01 尚未实现（退出码 11）\n",
	"sandbox_required": "Phase 01 变更只允许有标记的一次性沙箱\n",
	"root_required":    "该命令需要 root\n",
	"no_tty":           "无 TTY：不进入交互菜单\n",
}

var en = map[string]string{
	"help": `Idleleo Xray manager (Phase 01 candidate)
Usage: idleleo [--root PATH] [--lang zh|en|fr|fa|ru|ko] <command>

Commands:
  version              print version
  status               read-only status
  show                 read-only runtime and share information
  config inspect       read-only structured config view
  change set-inbound-port --sandbox PATH --port N --validator PATH
                       change one inbound port inside a disposable sandbox
  bridge audit|prepare|validate|activate|recover|status
                       audit, pre-flight, switch and recovery for legacy Bash installs
  schedule install|remove|run|status
                       native Go jobs (takeover of the legacy update/cert/GeoData/stats cron)
  stats                not implemented (exit 11)
  help                 show this help
`,
	"version":          "idleleo %s (go)\n",
	"usage":            "invalid command or arguments\n",
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
	"not_implemented":  "not implemented in Phase 01 (exit 11)\n",
	"sandbox_required": "Phase 01 mutations require a marked disposable sandbox\n",
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
