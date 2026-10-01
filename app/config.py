"""服务运行配置，全部可通过环境变量覆盖。"""
from __future__ import annotations

import os
from pathlib import Path


class Settings:
    # SQLite 数据库文件位置（容器内默认挂在 /data 下，便于持久化）
    DB_PATH: str = os.getenv("TLSV_DB_PATH", "/data/tlsv.db")
    # 服务监听地址与端口
    HOST: str = os.getenv("TLSV_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("TLSV_PORT", "8080"))
    # 启动时是否写入演示数据（Compose 默认开启，便于一键验证）
    SEED_DEMO: bool = os.getenv("TLSV_SEED_DEMO", "1") == "1"

    def ensure_dirs(self) -> None:
        Path(self.DB_PATH).parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
