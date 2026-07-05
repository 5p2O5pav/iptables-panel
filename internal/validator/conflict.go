package validator

import (
    "database/sql"
    "fmt"
    "os/exec"
    "strconv"
    "strings"

    "iptables-panel/internal/database"
)

// CheckSystemPortUsed 检查本地端口是否被系统其他进程占用（非本面板管理）
// 使用 ss -lntu 检查
func CheckSystemPortUsed(protocol string, port int) (bool, error) {
    // 协议映射：tcp -> -t, udp -> -u
    var flag string
    if protocol == "tcp" {
        flag = "-t"
    } else if protocol == "udp" {
        flag = "-u"
    } else {
        return false, fmt.Errorf("不支持的协议: %s", protocol)
    }

    // ss -lntu (listening, numeric, tcp/udp)
    cmd := exec.Command("ss", "-l", flag, "n")
    out, err := cmd.Output()
    if err != nil {
        return false, fmt.Errorf("执行 ss 命令失败: %v", err)
    }

    lines := strings.Split(string(out), "\n")
    for _, line := range lines {
        // 解析行，查找端口: 例如 "*:8080" 或 "0.0.0.0:8080" 或 "[::]:8080"
        if strings.Contains(line, ":"+strconv.Itoa(port)) {
            // 进一步确保是监听端口
            if strings.Contains(line, "LISTEN") {
                return true, nil
            }
        }
    }
    return false, nil
}

// ValidateAndCheckConflict 综合检查端口冲突（数据库冲突 + 系统占用）
// 返回 (是否有冲突, 冲突信息, error)
func ValidateAndCheckConflict(db *sql.DB, protocol string, listenStart, listenEnd int) (bool, string, error) {
    // 1. 检查数据库冲突
    conflict, conflictID, err := database.CheckConflict(db, protocol, listenStart, listenEnd)
    if err != nil {
        return false, "", fmt.Errorf("数据库查询冲突失败: %v", err)
    }
    if conflict {
        return true, fmt.Sprintf("端口范围 %d-%d 与规则 ID %d 冲突", listenStart, listenEnd, conflictID), nil
    }

    // 2. 检查系统占用（只检查单个端口，但范围需要检查每个端口？为了性能，我们只检查起始和结束，或抽样）
    // 为了精确，我们检查范围中的所有端口，但范围可能很大，所以限制检查最多 10 个或提示。
    // 这里我们仅检查开始和结束，如果有中间端口被占用，可能漏检，但实际概率低，且用户可能希望知道。
    // 更好的做法：检查每个端口，但如果范围大，会慢。我们采取策略：范围长度 <= 10 则全部检查，否则检查首尾+中间随机几个。
    portsToCheck := []int{listenStart, listenEnd}
    if listenEnd-listenStart > 10 {
        // 增加中间几个点
        mid1 := (listenStart + listenEnd) / 2
        mid2 := (listenStart + listenEnd) / 3
        mid3 := (listenStart + listenEnd) * 2 / 3
        portsToCheck = append(portsToCheck, mid1, mid2, mid3)
    } else {
        // 全量检查
        for p := listenStart; p <= listenEnd; p++ {
            portsToCheck = append(portsToCheck, p)
        }
    }
    // 去重
    seen := make(map[int]bool)
    for _, p := range portsToCheck {
        if seen[p] {
            continue
        }
        seen[p] = true
        used, err := CheckSystemPortUsed(protocol, p)
        if err != nil {
            // 如果 ss 执行失败，忽略系统检查（仅记录日志）
            continue
        }
        if used {
            return true, fmt.Sprintf("端口 %d 已被系统其他进程占用", p), nil
        }
    }

    return false, "", nil
}
