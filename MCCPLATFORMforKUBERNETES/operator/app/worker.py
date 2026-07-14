import json
import os
import sqlite3
import threading
import time
import urllib.request
from pathlib import Path

from drivers.kubernetes_driver import DeploySpec, InstanceStatus, KubernetesDeploymentDriver

DB_PATH      = os.getenv("MCP_PLATFORM_DB", "/data/mcp_platform.db")
CALLBACK_URL = os.getenv("MCP_PLATFORM_CALLBACK_URL", "http://mcp-platform:8080")


def dispatch_event(event: str, runtime_id: str, details: dict) -> None:
    payload = json.dumps({
        "event": event, "runtime_id": runtime_id,
        "timestamp": now_sql(), "details": details,
    }).encode()
    def _fire() -> None:
        try:
            req = urllib.request.Request(
                f"{CALLBACK_URL}/api/webhook-event",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=4)
        except Exception:
            pass
    threading.Thread(target=_fire, daemon=True).start()


def now_sql() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def audit(conn: sqlite3.Connection, action: str, target_id: str, details: str = "{}") -> None:
    conn.execute(
        "INSERT INTO audit_log(actor, action, target_type, target_id, details_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("operator", action, "runtime", target_id, details, now_sql()),
    )


def audit_json(conn: sqlite3.Connection, action: str, target_id: str, details: dict) -> None:
    audit(conn, action, target_id, json.dumps(details))


def log(conn: sqlite3.Connection, runtime_id: str, message: str, level: str = "info") -> None:
    conn.execute(
        "INSERT INTO runtime_logs(runtime_id, level, message, created_at) VALUES (?, ?, ?, ?)",
        (runtime_id, level, message, now_sql()),
    )


def build_deploy_spec(runtime: sqlite3.Row) -> DeploySpec:
    return DeploySpec(
        server_id=runtime["id"],
        name=runtime["name"],
        runtime_class=runtime["runtime_class"],
        runtime_image=runtime["image"],
        config_mount=runtime["config_path"],
    )


def run_action(driver: KubernetesDeploymentDriver, conn: sqlite3.Connection,
               request: sqlite3.Row) -> None:
    action     = request["action"]
    runtime_id = request["runtime_id"]

    runtime = conn.execute("SELECT * FROM runtimes WHERE id = ?", (runtime_id,)).fetchone()
    if not runtime:
        raise RuntimeError(f"runtime not found: {runtime_id}")

    if action in {"deploy", "redeploy"}:
        config_path = runtime["config_path"]
        if not config_path or not Path(config_path).exists():
            raise RuntimeError(f"config path missing: {config_path}")
        log(conn, runtime_id, f"Deploying runtime via Kubernetes driver")
        status = driver.apply(build_deploy_spec(runtime))
        conn.execute(
            "UPDATE runtimes SET status=?, endpoint_url=?, container_name=?, last_error=NULL, updated_at=? WHERE id=?",
            (status.state, status.endpoint_url, status.container_name, now_sql(), runtime_id),
        )
        log(conn, runtime_id, f"Runtime deployed: {status.endpoint_url}")
        audit_json(conn, "deploy_runtime", runtime_id,
                   {"deployment": status.container_name, "endpoint": status.endpoint_url})

    elif action == "rebuild_redeploy":
        image = runtime["image"]
        log(conn, runtime_id, f"Building image {image} via BuildConfig")
        try:
            driver.build_image(Path("/dev/null"), image)
        except NotImplementedError as exc:
            raise RuntimeError(str(exc))
        log(conn, runtime_id, f"BuildConfig triggered for {image}, deploying...")
        config_path = runtime["config_path"]
        if not config_path or not Path(config_path).exists():
            raise RuntimeError(f"config path missing: {config_path}")
        status = driver.apply(build_deploy_spec(runtime))
        conn.execute(
            "UPDATE runtimes SET status=?, endpoint_url=?, container_name=?, last_error=NULL, updated_at=? WHERE id=?",
            (status.state, status.endpoint_url, status.container_name, now_sql(), runtime_id),
        )
        log(conn, runtime_id, f"Runtime redeployed: {status.endpoint_url}")
        audit_json(conn, "rebuild_redeploy", runtime_id,
                   {"image": image, "endpoint": status.endpoint_url})

    elif action == "stop":
        status = driver.stop(runtime_id)
        conn.execute(
            "UPDATE runtimes SET status=?, updated_at=? WHERE id=?",
            (status.state, now_sql(), runtime_id),
        )
        log(conn, runtime_id, "Runtime stopped (Deployment scaled to 0)")
        audit_json(conn, "stop_runtime", runtime_id, {"deployment": status.container_name})

    elif action == "start":
        status = driver.start(runtime_id)
        conn.execute(
            "UPDATE runtimes SET status=?, endpoint_url=?, updated_at=? WHERE id=?",
            (status.state, status.endpoint_url, now_sql(), runtime_id),
        )
        log(conn, runtime_id, "Runtime started (Deployment scaled to 1)")
        audit_json(conn, "start_runtime", runtime_id, {"deployment": status.container_name})

    elif action == "restart":
        status = driver.restart(runtime_id)
        conn.execute(
            "UPDATE runtimes SET status=?, endpoint_url=?, updated_at=? WHERE id=?",
            (status.state, status.endpoint_url, now_sql(), runtime_id),
        )
        log(conn, runtime_id, "Runtime restarted (rollout restart)")
        audit_json(conn, "restart_runtime", runtime_id, {"deployment": status.container_name})

    elif action == "delete":
        status = driver.delete(runtime_id)
        conn.execute(
            "UPDATE runtimes SET status=?, endpoint_url=NULL, container_name=NULL, updated_at=? WHERE id=?",
            (status.state, now_sql(), runtime_id),
        )
        log(conn, runtime_id, "Runtime deleted (Deployment + Service + ConfigMap + Secret + Route removed)")
        audit_json(conn, "delete_runtime", runtime_id, {})

    elif action == "health":
        status = driver.status(runtime_id)
        conn.execute(
            "UPDATE runtimes SET status=?, last_error=?, updated_at=? WHERE id=?",
            (status.state, status.last_error, now_sql(), runtime_id),
        )
        log(conn, runtime_id, f"Health check: {status.state}")
        audit_json(conn, "health_refresh", runtime_id,
                   {"state": status.state, "error": status.last_error})

    elif action == "reload":
        # Na K8s: zaktualizuj ConfigMap i Secret, następnie rollout restart
        config_path = runtime["config_path"]
        if config_path and Path(config_path).exists():
            from drivers.kubernetes_driver import (
                _load_config_files, _load_env_vars, _make_configmap, _make_secret,
                _cm, _sec, NAMESPACE,
            )
            from kubernetes import client as k8s_client
            core = k8s_client.CoreV1Api()
            cp = Path(config_path)
            cm = _make_configmap(runtime_id, cp)
            sec = _make_secret(runtime_id, _load_env_vars(cp))
            core.replace_namespaced_config_map(_cm(runtime_id), NAMESPACE, cm)
            core.replace_namespaced_secret(_sec(runtime_id), NAMESPACE, sec)
        driver.restart(runtime_id)
        conn.execute("UPDATE runtimes SET last_error=NULL, updated_at=? WHERE id=?",
                     (now_sql(), runtime_id))
        log(conn, runtime_id, "Config reloaded (ConfigMap updated + rollout restart)")
        audit_json(conn, "reload_runtime", runtime_id, {})

    elif action == "logs":
        lines = driver.container_logs(runtime_id)
        for line in lines:
            log(conn, runtime_id, f"container: {line[:1000]}")
        audit_json(conn, "sync_logs", runtime_id, {"lines": len(lines)})

    else:
        raise RuntimeError(f"unknown action: {action}")


def run_image_build(driver: KubernetesDeploymentDriver, conn: sqlite3.Connection,
                    request: sqlite3.Row) -> None:
    build_id = request["id"]
    image    = request["image"]
    log(conn, build_id, f"Triggering BuildConfig for image {image}")
    try:
        driver.build_image(Path("/dev/null"), image)
    except NotImplementedError as exc:
        raise RuntimeError(str(exc))
    log(conn, build_id, f"BuildConfig triggered: {image}")
    audit_json(conn, "build_runtime_image", build_id, {"image": image})


def sync_runtime_statuses(driver: KubernetesDeploymentDriver,
                          conn: sqlite3.Connection) -> None:
    statuses = driver.sync_statuses()
    status_by_id = {s.server_id: s for s in statuses}
    runtimes = conn.execute(
        "SELECT id FROM runtimes WHERE container_name IS NOT NULL"
    ).fetchall()
    for runtime in runtimes:
        rid = runtime["id"]
        if rid in status_by_id:
            conn.execute(
                "UPDATE runtimes SET status=?, updated_at=? WHERE id=?",
                (status_by_id[rid].state, now_sql(), rid),
            )
        else:
            conn.execute(
                "UPDATE runtimes SET status=?, container_name=NULL, endpoint_url=NULL, updated_at=? WHERE id=?",
                ("missing", now_sql(), rid),
            )
            dispatch_event("health_failed", rid, {"state": "missing"})


def loop() -> None:
    driver = KubernetesDeploymentDriver()
    while True:
        try:
            with connect() as conn:
                sync_runtime_statuses(driver, conn)
                requests = conn.execute(
                    "SELECT * FROM deployment_requests WHERE status='pending' ORDER BY id LIMIT 5"
                ).fetchall()
                for request in requests:
                    runtime_id = request["runtime_id"]
                    conn.execute(
                        "UPDATE deployment_requests SET status=?, updated_at=? WHERE id=?",
                        ("running", now_sql(), request["id"]),
                    )
                    conn.commit()
                    try:
                        run_action(driver, conn, request)
                        conn.execute(
                            "UPDATE deployment_requests SET status=?, updated_at=? WHERE id=?",
                            ("done", now_sql(), request["id"]),
                        )
                    except Exception as exc:
                        conn.execute(
                            "UPDATE deployment_requests SET status=?, error=?, updated_at=? WHERE id=?",
                            ("failed", str(exc), now_sql(), request["id"]),
                        )
                        conn.execute(
                            "UPDATE runtimes SET status=?, last_error=?, updated_at=? WHERE id=?",
                            ("failed", str(exc), now_sql(), runtime_id),
                        )
                        log(conn, runtime_id, f"Action failed: {exc}", "error")
                        audit(conn, "action_failed", runtime_id, json.dumps({"error": str(exc)}))
                        dispatch_event("runtime_failed", runtime_id,
                                       {"error": str(exc), "action": request["action"]})

                image_builds = conn.execute(
                    "SELECT * FROM runtime_image_builds WHERE status='pending' ORDER BY created_at LIMIT 2"
                ).fetchall()
                for build in image_builds:
                    build_id = build["id"]
                    conn.execute(
                        "UPDATE runtime_image_builds SET status=?, updated_at=? WHERE id=?",
                        ("running", now_sql(), build_id),
                    )
                    conn.commit()
                    try:
                        run_image_build(driver, conn, build)
                        conn.execute(
                            "UPDATE runtime_image_builds SET status=?, error=NULL, updated_at=? WHERE id=?",
                            ("done", now_sql(), build_id),
                        )
                    except Exception as exc:
                        conn.execute(
                            "UPDATE runtime_image_builds SET status=?, error=?, updated_at=? WHERE id=?",
                            ("failed", str(exc), now_sql(), build_id),
                        )
                        log(conn, build_id, f"Image build failed: {exc}", "error")
                        audit(conn, "build_failed", build_id, json.dumps({"error": str(exc)}))
                conn.commit()
        except Exception:
            time.sleep(5)
        time.sleep(2)


if __name__ == "__main__":
    loop()
