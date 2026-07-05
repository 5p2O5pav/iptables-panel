package handler

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "strconv"
    "strings"
    "time"

    "iptables-panel/internal/config"
    "iptables-panel/internal/database"
    "iptables-panel/internal/iptables"
    "iptables-panel/internal/validator"
)

type WebHandler struct {
    db      *sql.DB
    iptMgr  *iptables.Manager
    cfg     *config.Config
    tmpl    *template.Template
}

func NewWebHandler(db *sql.DB, iptMgr *iptables.Manager, cfg *config.Config) *WebHandler {
    // 解析模板（内联模板，直接在代码中定义，避免外部文件）
    tmpl := template.Must(template.New("index").Parse(indexTemplate))
    return &WebHandler{
        db:     db,
        iptMgr: iptMgr,
        cfg:    cfg,
        tmpl:   tmpl,
    }
}

// Index 渲染主页面
func (h *WebHandler) Index(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    // 获取规则列表
    rules, err := database.GetAllRules(h.db)
    if err != nil {
        http.Error(w, "获取规则失败: "+err.Error(), http.StatusInternalServerError)
        return
    }
    data := struct {
        Rules []database.ForwardRule
    }{Rules: rules}
    if err := h.tmpl.Execute(w, data); err != nil {
        log.Printf("模板渲染失败: %v", err)
    }
}

// HandleRules 处理 /api/rules 的 GET 和 POST
func (h *WebHandler) HandleRules(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    switch r.Method {
    case http.MethodGet:
        rules, err := database.GetAllRules(h.db)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 500, "message": err.Error()})
            return
        }
        json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "data": rules})

    case http.MethodPost:
        // 解析 JSON 请求体
        var req struct {
            Protocol    string `json:"protocol"`
            ListenStart int    `json:"listen_start"`
            ListenEnd   int    `json:"listen_end"`
            TargetIP    string `json:"target_ip"`
            TargetStart int    `json:"target_start"`
            TargetEnd   int    `json:"target_end"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "无效的 JSON: " + err.Error()})
            return
        }

        // 参数校验
        if req.Protocol != "tcp" && req.Protocol != "udp" {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "协议必须是 tcp 或 udp"})
            return
        }
        if req.ListenStart < 1 || req.ListenStart > 65535 || req.ListenEnd < 1 || req.ListenEnd > 65535 || req.ListenStart > req.ListenEnd {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "本地端口范围无效"})
            return
        }
        if req.TargetStart < 1 || req.TargetStart > 65535 || req.TargetEnd < 1 || req.TargetEnd > 65535 || req.TargetStart > req.TargetEnd {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "目标端口范围无效"})
            return
        }
        // 目标 IP 简单校验
        if req.TargetIP == "" || strings.Count(req.TargetIP, ".") != 3 {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "目标 IP 格式无效"})
            return
        }
        // 检查范围长度是否一致（iptables 要求起始端口对齐，但长度必须相等）
        if (req.ListenEnd - req.ListenStart) != (req.TargetEnd - req.TargetStart) {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "本地端口范围与目标端口范围长度必须一致"})
            return
        }

        // 冲突检测（数据库 + 系统占用）
        conflict, msg, err := validator.ValidateAndCheckConflict(h.db, req.Protocol, req.ListenStart, req.ListenEnd)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 500, "message": "冲突检测失败: " + err.Error()})
            return
        }
        if conflict {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 409, "message": msg})
            return
        }

        // 构建规则对象
        rule := &database.ForwardRule{
            Protocol:    req.Protocol,
            ListenStart: req.ListenStart,
            ListenEnd:   req.ListenEnd,
            TargetIP:    req.TargetIP,
            TargetStart: req.TargetStart,
            TargetEnd:   req.TargetEnd,
        }

        // 先插入数据库（获取 ID），再应用 iptables，如果 iptables 失败则回滚数据库
        id, err := database.InsertRule(h.db, rule)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 500, "message": "写入数据库失败: " + err.Error()})
            return
        }
        rule.ID = int(id)

        // 应用 iptables
        if err := h.iptMgr.AddRule(*rule); err != nil {
            // 回滚数据库
            _ = database.DeleteRuleByID(h.db, int(id))
            json.NewEncoder(w).Encode(map[string]interface{}{"code": 500, "message": "添加 iptables 规则失败: " + err.Error()})
            return
        }

        // 持久化
        if err := iptables.PersistRules(h.cfg.IptablesSaveCmd); err != nil {
            // 持久化失败只记录日志，不影响返回（因为规则已生效，重启后可能丢失，但用户可手动保存）
            log.Printf("持久化失败: %v", err)
        }

        json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "添加成功", "id": id})

    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

// HandleRuleByID 处理 DELETE /api/rules/{id}
func (h *WebHandler) HandleRuleByID(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    // 提取 ID
    path := strings.TrimPrefix(r.URL.Path, "/api/rules/")
    id, err := strconv.Atoi(path)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "无效的 ID"})
        return
    }

    // 先获取规则详情（以便删除 iptables）
    rules, err := database.GetAllRules(h.db)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{"code": 500, "message": err.Error()})
        return
    }
    var targetRule *database.ForwardRule
    for _, r := range rules {
        if r.ID == id {
            targetRule = &r
            break
        }
    }
    if targetRule == nil {
        json.NewEncoder(w).Encode(map[string]interface{}{"code": 404, "message": "规则不存在"})
        return
    }

    // 删除 iptables 规则
    if err := h.iptMgr.RemoveRule(*targetRule); err != nil {
        // 即使删除失败，也尝试从数据库删除，但记录错误
        log.Printf("删除 iptables 规则失败 (ID %d): %v", id, err)
        // 我们继续删除数据库，因为用户希望清除，如果 iptables 规则手动残留，可以后续清理
    }

    // 从数据库删除
    ok, err := database.DeleteRuleByID(h.db, id)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{"code": 500, "message": "数据库删除失败: " + err.Error()})
        return
    }
    if !ok {
        json.NewEncoder(w).Encode(map[string]interface{}{"code": 404, "message": "规则不存在"})
        return
    }

    // 持久化
    if err := iptables.PersistRules(h.cfg.IptablesSaveCmd); err != nil {
        log.Printf("持久化失败: %v", err)
    }

    json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "删除成功"})
}

// HandleFlush 处理清空所有规则
func (h *WebHandler) HandleFlush(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    // 获取所有规则，逐个删除 iptables，然后清空数据库
    rules, err := database.GetAllRules(h.db)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{"code": 500, "message": err.Error()})
        return
    }
    for _, rule := range rules {
        _ = h.iptMgr.RemoveRule(rule) // 忽略错误，尽量删除
    }
    if err := database.DeleteAllRules(h.db); err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{"code": 500, "message": "清空数据库失败: " + err.Error()})
        return
    }
    // 持久化（清空后保存空规则）
    if err := iptables.PersistRules(h.cfg.IptablesSaveCmd); err != nil {
        log.Printf("持久化失败: %v", err)
    }
    json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "已清空所有规则"})
}

// 内联 HTML 模板
const indexTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>iptables 转发面板</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { margin-top: 0; }
        .form-group { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 15px; }
        .form-group label { font-weight: bold; }
        .form-group input, .form-group select { padding: 6px 10px; border: 1px solid #ccc; border-radius: 4px; }
        .form-group button { padding: 6px 18px; background: #007bff; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
        .form-group button:hover { background: #0056b3; }
        .form-group .danger { background: #dc3545; }
        .form-group .danger:hover { background: #c82333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
        .delete-btn { background: #dc3545; color: #fff; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; }
        .delete-btn:hover { background: #c82333; }
        .msg { padding: 10px; margin-bottom: 15px; border-radius: 4px; display: none; }
        .msg.error { background: #f8d7da; color: #721c24; display: block; }
        .msg.success { background: #d4edda; color: #155724; display: block; }
        .range-help { font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
<div class="container">
    <h1>iptables 端口转发面板</h1>
    <div id="msg" class="msg"></div>

    <h2>添加转发规则</h2>
    <div class="form-group">
        <label>协议: <select id="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
        <label>本地端口: <input type="number" id="listen_start" value="10000" min="1" max="65535"> - <input type="number" id="listen_end" value="10010" min="1" max="65535"></label>
        <label>目标 IP: <input type="text" id="target_ip" value="1.2.3.4"></label>
        <label>目标端口: <input type="number" id="target_start" value="20000" min="1" max="65535"> - <input type="number" id="target_end" value="20010" min="1" max="65535"></label>
        <button id="addBtn">添加</button>
        <button id="flushBtn" class="danger">清空全部</button>
    </div>
    <div class="range-help">提示：端口范围长度需一致，单端口时起始和结束相同。</div>

    <h2>当前规则列表 (<span id="count">0</span>)</h2>
    <table>
        <thead><tr><th>ID</th><th>协议</th><th>本地端口</th><th>目标地址</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody id="ruleTableBody"></tbody>
    </table>
</div>

<script>
    function showMsg(text, type) {
        const msg = document.getElementById('msg');
        msg.textContent = text;
        msg.className = 'msg ' + (type || 'error');
        setTimeout(() => { msg.className = 'msg'; }, 5000);
    }

    async function loadRules() {
        const resp = await fetch('/api/rules');
        const data = await resp.json();
        if (data.code !== 0) {
            showMsg('加载规则失败: ' + data.message, 'error');
            return;
        }
        const rules = data.data || [];
        const tbody = document.getElementById('ruleTableBody');
        tbody.innerHTML = '';
        document.getElementById('count').textContent = rules.length;
        for (const r of rules) {
            const tr = document.createElement('tr');
            const listenPort = r.listen_start === r.listen_end ? r.listen_start : r.listen_start + '-' + r.listen_end;
            const targetPort = r.target_start === r.target_end ? r.target_start : r.target_start + '-' + r.target_end;
            const targetAddr = r.target_ip + ':' + targetPort;
            const createdAt = r.created_at || '';
            tr.innerHTML = '<td>' + r.id + '</td><td>' + r.protocol.toUpperCase() + '</td><td>' + listenPort + '</td><td>' + targetAddr + '</td><td>' + createdAt + '</td><td><button class="delete-btn" data-id="' + r.id + '">删除</button></td>';
            tbody.appendChild(tr);
        }
        // 绑定删除事件
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', async function() {
                const id = this.dataset.id;
                if (!confirm('确定要删除规则 ID ' + id + ' 吗？')) return;
                const resp = await fetch('/api/rules/' + id, { method: 'DELETE' });
                const data = await resp.json();
                if (data.code === 0) {
                    showMsg('删除成功', 'success');
                    loadRules();
                } else {
                    showMsg('删除失败: ' + data.message, 'error');
                }
            });
        });
    }

    document.getElementById('addBtn').addEventListener('click', async function() {
        const protocol = document.getElementById('protocol').value;
        const listen_start = parseInt(document.getElementById('listen_start').value);
        const listen_end = parseInt(document.getElementById('listen_end').value);
        const target_ip = document.getElementById('target_ip').value.trim();
        const target_start = parseInt(document.getElementById('target_start').value);
        const target_end = parseInt(document.getElementById('target_end').value);
        if (isNaN(listen_start) || isNaN(listen_end) || isNaN(target_start) || isNaN(target_end) || !target_ip) {
            showMsg('请填写完整有效的数据', 'error');
            return;
        }
        const payload = { protocol, listen_start, listen_end, target_ip, target_start, target_end };
        const resp = await fetch('/api/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (data.code === 0) {
            showMsg('添加成功，ID: ' + data.id, 'success');
            loadRules();
            // 不清空表单，方便连续添加
        } else {
            showMsg('添加失败: ' + data.message, 'error');
        }
    });

    document.getElementById('flushBtn').addEventListener('click', async function() {
        if (!confirm('确定要清空所有规则吗？此操作不可撤销！')) return;
        const resp = await fetch('/api/rules/flush', { method: 'POST' });
        const data = await resp.json();
        if (data.code === 0) {
            showMsg('清空成功', 'success');
            loadRules();
        } else {
            showMsg('清空失败: ' + data.message, 'error');
        }
    });

    // 初始加载
    loadRules();
</script>
</body>
</html>`
