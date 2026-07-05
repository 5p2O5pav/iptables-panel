package database

import (
    "database/sql"
    "fmt"
)

type ForwardRule struct {
    ID          int
    Protocol    string // "tcp" 或 "udp"
    ListenStart int
    ListenEnd   int
    TargetIP    string
    TargetStart int
    TargetEnd   int
}

// GetAllRules 获取所有规则
func GetAllRules(db *sql.DB) ([]ForwardRule, error) {
    rows, err := db.Query(`SELECT id, protocol, listen_start, listen_end, target_ip, target_start, target_end FROM forward_rules ORDER BY id`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var rules []ForwardRule
    for rows.Next() {
        var r ForwardRule
        if err := rows.Scan(&r.ID, &r.Protocol, &r.ListenStart, &r.ListenEnd, &r.TargetIP, &r.TargetStart, &r.TargetEnd); err != nil {
            return nil, err
        }
        rules = append(rules, r)
    }
    return rules, nil
}

// InsertRule 插入规则，返回插入的 ID
func InsertRule(db *sql.DB, r *ForwardRule) (int64, error) {
    res, err := db.Exec(
        `INSERT INTO forward_rules (protocol, listen_start, listen_end, target_ip, target_start, target_end) VALUES (?, ?, ?, ?, ?, ?)`,
        r.Protocol, r.ListenStart, r.ListenEnd, r.TargetIP, r.TargetStart, r.TargetEnd,
    )
    if err != nil {
        return 0, err
    }
    return res.LastInsertId()
}

// DeleteRuleByID 根据 ID 删除规则
func DeleteRuleByID(db *sql.DB, id int) (bool, error) {
    res, err := db.Exec(`DELETE FROM forward_rules WHERE id = ?`, id)
    if err != nil {
        return false, err
    }
    rows, _ := res.RowsAffected()
    return rows > 0, nil
}

// DeleteAllRules 清空所有规则
func DeleteAllRules(db *sql.DB) error {
    _, err := db.Exec(`DELETE FROM forward_rules`)
    return err
}

// CheckConflict 检查与现有规则是否有端口范围重叠（同一协议下）
// 返回 (是否存在冲突, 冲突规则ID, error)
func CheckConflict(db *sql.DB, protocol string, listenStart, listenEnd int) (bool, int, error) {
    var conflictID int
    err := db.QueryRow(
        `SELECT id FROM forward_rules 
         WHERE protocol = ? 
         AND (listen_start <= ? AND listen_end >= ?)`,
        protocol, listenEnd, listenStart,
    ).Scan(&conflictID)
    if err == sql.ErrNoRows {
        return false, 0, nil
    }
    if err != nil {
        return false, 0, err
    }
    return true, conflictID, nil
}
