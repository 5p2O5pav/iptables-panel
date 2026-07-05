package main

import (
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"

    "iptables-panel/internal/config"
    "iptables-panel/internal/database"
    "iptables-panel/internal/handler"
    "iptables-panel/internal/iptables"
)

func main() {
    // 解析命令行参数
    port := flag.String("port", "8080", "Web 面板监听端口")
    dbPath := flag.String("db", "./rules.db", "SQLite 数据库文件路径")
    flag.Parse()

    // 加载配置
    cfg := &config.Config{
        WebPort:         *port,
        DBPath:          *dbPath,
        IptablesSaveCmd: "/sbin/iptables-save",
        IptablesRestoreCmd: "/sbin/iptables-restore",
    }

    // 初始化数据库
    db, err := database.InitDB(cfg.DBPath)
    if err != nil {
        log.Fatalf("初始化数据库失败: %v", err)
    }
    defer db.Close()

    // 初始化 iptables 管理器
    iptMgr, err := iptables.NewManager()
    if err != nil {
        log.Fatalf("初始化 iptables 管理器失败: %v", err)
    }

    // 程序启动时，从数据库恢复所有规则到内核（幂等）
    rules, err := database.GetAllRules(db)
    if err != nil {
        log.Printf("警告: 读取数据库规则失败: %v", err)
    } else {
        log.Printf("正在恢复 %d 条规则到内核...", len(rules))
        for _, r := range rules {
            if err := iptMgr.AddRule(r); err != nil {
                log.Printf("恢复规则 ID %d 失败: %v", r.ID, err)
            }
        }
        // 规则恢复后立即持久化一次，确保一致
        if len(rules) > 0 {
            _ = iptables.PersistRules(cfg.IptablesSaveCmd)
        }
    }

    // 创建 HTTP 处理器
    webHandler := handler.NewWebHandler(db, iptMgr, cfg)

    // 注册路由
    http.HandleFunc("/", webHandler.Index)
    http.HandleFunc("/api/rules", webHandler.HandleRules)
    http.HandleFunc("/api/rules/", webHandler.HandleRuleByID) // DELETE /api/rules/{id}
    http.HandleFunc("/api/rules/flush", webHandler.HandleFlush)

    // 静态文件（可选，如果使用独立的 css/js 则需提供）
    // 我们将在代码中嵌入模板和静态资源，或者通过 http.FileServer 提供
    // 为了简便，我们把样式放在模板内部，所以这里不配置 static 路由

    // 启动 HTTP 服务
    addr := ":" + cfg.WebPort
    log.Printf("面板启动，监听地址: http://0.0.0.0%s", addr)
    srv := &http.Server{Addr: addr}

    // 优雅关闭
    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("HTTP 服务启动失败: %v", err)
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    log.Println("收到退出信号，正在关闭服务...")
    if err := srv.Close(); err != nil {
        log.Printf("关闭服务出错: %v", err)
    }
    log.Println("服务已退出")
}
