package iptables

import (
    "os/exec"
    "log"
)

// PersistRules 执行 iptables-save 并保存到 /etc/iptables/rules.v4
func PersistRules(saveCmd string) error {
    // 先保存到临时文件再移动，避免写一半断电
    tmpFile := "/etc/iptables/rules.v4.tmp"
    cmd := exec.Command("sh", "-c", saveCmd+" > "+tmpFile)
    if err := cmd.Run(); err != nil {
        return err
    }
    // 移动
    mvCmd := exec.Command("mv", tmpFile, "/etc/iptables/rules.v4")
    if err := mvCmd.Run(); err != nil {
        return err
    }
    log.Println("iptables 规则已持久化到 /etc/iptables/rules.v4")
    return nil
}
