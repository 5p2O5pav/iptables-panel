package database

import (
    "database/sql"
    "log"

    _ "github.com/mattn/go-sqlite3"
)

func InitDB(dbPath string) (*sql.DB, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, err
    }

    // 创建表
    createTableSQL := `
    CREATE TABLE IF NOT EXISTS forward_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol TEXT NOT NULL,
        listen_start INTEGER NOT NULL,
        listen_end INTEGER NOT NULL,
        target_ip TEXT NOT NULL,
        target_start INTEGER NOT NULL,
        target_end INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_protocol_listen ON forward_rules(protocol, listen_start, listen_end);
    `
    if _, err := db.Exec(createTableSQL); err != nil {
        return nil, err
    }

    log.Println("数据库初始化成功")
    return db, nil
}
