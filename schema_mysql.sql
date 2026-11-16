-- Real-Time IDS: MySQL schema
-- Run once: mysql -u ids_user -p ids_db < schema_mysql.sql
-- (Optional — app/main.py also auto-creates this table on startup via SQLAlchemy.)

CREATE TABLE IF NOT EXISTS flows (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    ts              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- when the flow was captured
    src_ip          VARCHAR(45),
    src_port        INT,
    dst_ip          VARCHAR(45),
    dst_port        INT,
    protocol        VARCHAR(10),                                  -- TCP / UDP / ICMP / Other
    predicted_label VARCHAR(64) NOT NULL,                          -- 'Benign' or attack class name
    is_attack       BOOLEAN NOT NULL DEFAULT FALSE,
    confidence      FLOAT,                                         -- 0..1, model's confidence if available
    severity        VARCHAR(16),                                   -- Low / Medium / High / Critical / NULL for benign
    flow_duration   DOUBLE,
    tot_fwd_pkts    INT,
    tot_bwd_pkts    INT,
    features        JSON,                                          -- full 69-feature vector (audit / retraining)
    acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_flows_ts          ON flows (ts);
CREATE INDEX idx_flows_is_attack   ON flows (is_attack);
CREATE INDEX idx_flows_label       ON flows (predicted_label);
CREATE INDEX idx_flows_protocol    ON flows (protocol);
CREATE INDEX idx_flows_src_ip      ON flows (src_ip);
CREATE INDEX idx_flows_dst_ip      ON flows (dst_ip);
