import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, Any
from .core import AuditStatus, ModuleState
from .db import open_db, init_db, insert_audit, update_audit_status, finish_audit, upsert_module, add_event, purge_db
from .jsonlog import build_logger
from .utils import new_audit_id, reset_dir
from .store import Store

class AuditRunner:
    def __init__(self, workdir: Path, db_path: Path):
        self.workdir = workdir
        self.db_path = db_path

    def run_audit(self, modules: Iterable, context: dict[str, Any]) -> str:
        reset_runs = bool(context.get("reset_previous_runs", True))
        reset_db = bool(context.get("reset_database", True))
        if reset_runs:
            reset_dir(self.workdir)
        else:
            self.workdir.mkdir(parents=True, exist_ok=True)
        audit_id = new_audit_id()
        audit_dir = self.workdir / audit_id
        audit_dir.mkdir(parents=True, exist_ok=True)
        logfile = audit_dir / "events.jsonl"
        level = str(context.get("log_level", "DEBUG")).upper()
        logger = build_logger(logfile, level)

        conn = open_db(self.db_path)
        init_db(conn)
        if reset_db:
            purge_db(conn)
            init_db(conn)

        def log(level_str: str, module: str | None, message: str, data: Any = None) -> None:
            add_event(conn, audit_id, level_str, module, message, json.dumps(data) if data is not None else None)
            lvl = level_str.upper()
            if lvl == "DEBUG":
                logger.debug(message, extra={"sb_module": module, "data": data})
            elif lvl == "INFO":
                logger.info(message, extra={"sb_module": module, "data": data})
            elif lvl == "WARNING":
                logger.warning(message, extra={"sb_module": module, "data": data})
            elif lvl == "ERROR":
                logger.error(message, extra={"sb_module": module, "data": data})
            else:
                logger.info(message, extra={"sb_module": module, "data": data})

        insert_audit(conn, audit_id, AuditStatus.PENDING.value)
        update_audit_status(conn, audit_id, AuditStatus.RUNNING.value)
        log("INFO", None, "audit_started", {"audit_id": audit_id, "workdir": str(self.workdir)})

        mod_names = [m.name for m in modules]
        log("DEBUG", None, "modules_registered", {"modules": mod_names})

        for module in modules:
            name = module.name
            upsert_module(conn, audit_id, name, ModuleState.PENDING.value, None, None, False, None, None)

        store = Store(conn, audit_id, audit_dir)

        for module in modules:
            name = module.name
            started = datetime.utcnow().isoformat()
            upsert_module(conn, audit_id, name, ModuleState.RUNNING.value, started, None, False, None, None)
            log("INFO", name, "module_started", None)
            try:
                ctx = dict(context, audit_id=audit_id, audit_dir=str(audit_dir))
                ctx["log"] = log
                ctx["store"] = store
                log("DEBUG", name, "module_context", {"context_keys": sorted(list(ctx.keys()))})
                ok, fatal, message, data = module.run(ctx)
                state = ModuleState.SUCCESS.value if ok else ModuleState.FAILED.value
                finished = datetime.utcnow().isoformat()
                upsert_module(conn, audit_id, name, state, started, finished, fatal, message, json.dumps(data) if data is not None else None)
                log("DEBUG", name, "module_result", {"ok": ok, "fatal": fatal, "message": message, "data": data})
                log("INFO" if ok else "ERROR", name, "module_finished", {"ok": ok, "fatal": fatal, "message": message})
                if fatal and not ok:
                    finish_audit(conn, audit_id, AuditStatus.FAILED.value)
                    log("ERROR", name, "audit_aborted_fatal", None)
                    return audit_id
            except Exception as e:
                finished = datetime.utcnow().isoformat()
                upsert_module(conn, audit_id, name, ModuleState.FAILED.value, started, finished, True, str(e), None)
                log("ERROR", name, "module_exception", {"error": str(e)})
                finish_audit(conn, audit_id, AuditStatus.FAILED.value)
                log("ERROR", name, "audit_aborted_exception", None)
                return audit_id
        finish_audit(conn, audit_id, AuditStatus.SUCCESS.value)
        log("INFO", None, "audit_finished", None)
        return audit_id
