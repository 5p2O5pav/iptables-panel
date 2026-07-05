package iptables

import (
    "fmt"
    "strconv"
    "strings"

    "github.com/coreos/go-iptables/iptables"
    "iptables-panel/internal/database"
)

type Manager struct {
    ipt *iptables.IPTables
}

func NewManager() (*Manager, error) {
    ipt, err := iptables.New()
    if err != nil {
        return nil, err
    }
    return &Manager{ipt: ipt}, nil
}

// buildPortSpec 构建端口字符串，单端口或范围
func buildPortSpec(start, end int) string {
    if start == end {
        return strconv.Itoa(start)
    }
    return fmt.Sprintf("%d:%d", start, end)
}

// AddRule 添加一条转发规则（包括DNAT、MASQUERADE、放行）
func (m *Manager) AddRule(r database.ForwardRule) error {
    proto := r.Protocol
    listenPort := buildPortSpec(r.ListenStart, r.ListenEnd)
    targetPort := buildPortSpec(r.TargetStart, r.TargetEnd)
    target := fmt.Sprintf("%s:%s", r.TargetIP, targetPort) // 用于 DNAT

    // 1. DNAT: PREROUTING
    if err := m.ipt.AppendUnique("nat", "PREROUTING", "-p", proto, "--dport", listenPort, "-j", "DNAT", "--to-destination", target); err != nil {
        return fmt.Errorf("添加 DNAT 失败: %v", err)
    }

    // 2. MASQUERADE: POSTROUTING
    // 注意：MASQUERADE 需要匹配目标端口，但直接匹配目标端口可能不准确，
    // 更通用的是匹配输出接口或目标地址，但为了简化，我们使用 --dport 匹配目标端口
    // 但 iptables 的 POSTROUTING 链中，--dport 配合 -p 和 --dport 是有效的（在 nat 表 POSTROUTING 中，数据包已经过 DNAT，所以目标端口已变）
    // 这里我们匹配协议和目标端口（映射后的端口），确保只对转发的流量做 MASQUERADE
    if err := m.ipt.AppendUnique("nat", "POSTROUTING", "-p", proto, "--dport", targetPort, "-j", "MASQUERADE"); err != nil {
        // 如果失败，回滚 DNAT
        _ = m.ipt.Delete("nat", "PREROUTING", "-p", proto, "--dport", listenPort, "-j", "DNAT", "--to-destination", target)
        return fmt.Errorf("添加 MASQUERADE 失败: %v", err)
    }

    // 3. 放行 INPUT (本地监听端口)
    if err := m.ipt.AppendUnique("filter", "INPUT", "-p", proto, "--dport", listenPort, "-j", "ACCEPT"); err != nil {
        // 回滚前两条
        _ = m.ipt.Delete("nat", "PREROUTING", "-p", proto, "--dport", listenPort, "-j", "DNAT", "--to-destination", target)
        _ = m.ipt.Delete("nat", "POSTROUTING", "-p", proto, "--dport", targetPort, "-j", "MASQUERADE")
        return fmt.Errorf("添加 INPUT ACCEPT 失败: %v", err)
    }

    // 4. 放行 FORWARD (转发的数据包)
    if err := m.ipt.AppendUnique("filter", "FORWARD", "-p", proto, "--dport", targetPort, "-j", "ACCEPT"); err != nil {
        // 回滚
        _ = m.ipt.Delete("nat", "PREROUTING", "-p", proto, "--dport", listenPort, "-j", "DNAT", "--to-destination", target)
        _ = m.ipt.Delete("nat", "POSTROUTING", "-p", proto, "--dport", targetPort, "-j", "MASQUERADE")
        _ = m.ipt.Delete("filter", "INPUT", "-p", proto, "--dport", listenPort, "-j", "ACCEPT")
        return fmt.Errorf("添加 FORWARD ACCEPT 失败: %v", err)
    }

    return nil
}

// RemoveRule 根据规则删除对应的 iptables 规则（使用精确匹配）
func (m *Manager) RemoveRule(r database.ForwardRule) error {
    proto := r.Protocol
    listenPort := buildPortSpec(r.ListenStart, r.ListenEnd)
    targetPort := buildPortSpec(r.TargetStart, r.TargetEnd)
    target := fmt.Sprintf("%s:%s", r.TargetIP, targetPort)

    // 删除顺序与添加相反
    // 1. 删除 FORWARD ACCEPT
    _ = m.ipt.Delete("filter", "FORWARD", "-p", proto, "--dport", targetPort, "-j", "ACCEPT")

    // 2. 删除 INPUT ACCEPT
    _ = m.ipt.Delete("filter", "INPUT", "-p", proto, "--dport", listenPort, "-j", "ACCEPT")

    // 3. 删除 MASQUERADE
    _ = m.ipt.Delete("nat", "POSTROUTING", "-p", proto, "--dport", targetPort, "-j", "MASQUERADE")

    // 4. 删除 DNAT
    if err := m.ipt.Delete("nat", "PREROUTING", "-p", proto, "--dport", listenPort, "-j", "DNAT", "--to-destination", target); err != nil {
        // 如果 DNAT 删除失败，可能是规则不存在，但我们仍返回错误以提示
        return fmt.Errorf("删除 DNAT 失败: %v", err)
    }
    return nil
}

// RemoveAllRules 清空本面板创建的所有规则（通过遍历数据库规则删除）
// 此函数由 handler 调用，传入规则列表逐个删除
// 这里只是实现单条删除，批量删除在 handler 中循环调用 RemoveRule
