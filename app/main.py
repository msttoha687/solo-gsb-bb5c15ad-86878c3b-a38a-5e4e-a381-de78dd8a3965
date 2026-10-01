"""FastAPI 路由层。"""
from __future__ import annotations

import contextlib

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse

from . import db, service
from .models import (
    CertificateImport,
    EvaluateRequest,
    PlanCreate,
    ServiceWindowCreate,
    TrustRootImport,
)

API = "/api/v1"


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="TLS Certificate Renewal Verification Service",
    version="1.0.0",
    description=(
        "离线 TLS 证书换发核验服务：导入 PEM 证书链与分版本信任根，"
        "登记证书服务窗口，校验 X.509 链并评估指定区间内的证书覆盖断档，"
        "仅无断档计划可批准。"
    ),
    lifespan=lifespan,
)


@app.exception_handler(service.ApiError)
async def api_error_handler(request: Request, exc: service.ApiError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/")
def index():
    return {"service": app.title, "version": app.version, "docs": "/docs", "api": API}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# ----------------------------- 信任根版本 -----------------------------

@app.post(f"{API}/trust-roots", status_code=201, tags=["trust-roots"])
def import_trust_root(body: TrustRootImport):
    """导入一个版本的本地信任根（PEM  bundle，可含多张根证书）。

    首个导入的版本自动置为在用版本。PEM 格式错误返回 400，版本重复返回 409。
    """
    return service.import_trust_root(body.version, body.pem)


@app.get(f"{API}/trust-roots", tags=["trust-roots"])
def list_trust_roots():
    return {"items": service.list_trust_roots()}


@app.post(f"{API}/trust-roots/{{version}}/activate", tags=["trust-roots"])
def activate_trust_root(version: str):
    """切换在用信任根版本；冻结版本不一致的已批准计划转为待复核。"""
    return service.activate_trust_root(version)


# ----------------------------- 证书 -----------------------------

@app.post(f"{API}/certificates", status_code=201, tags=["certificates"])
def import_certificate(body: CertificateImport):
    """导入 PEM 证书链（第一个块为叶子证书，其后为中间证书）。

    PEM 格式错误返回 400，证书指纹重复返回 409。
    """
    return service.import_certificate(body.pem, body.label)


@app.get(f"{API}/certificates", tags=["certificates"])
def list_certificates():
    return {"items": service.list_certificates()}


@app.get(f"{API}/certificates/{{fingerprint}}", tags=["certificates"])
def get_certificate(fingerprint: str):
    return service.get_certificate(fingerprint)


# ----------------------------- 服务窗口 -----------------------------

@app.post(f"{API}/service-windows", status_code=201, tags=["service-windows"])
def create_service_window(body: ServiceWindowCreate):
    """为域名登记证书服务窗口，UTC 半开区间 [start, end)。

    role: current=现用, planned=拟启用。窗口无效返回 400；
    窗口变动会使该域名下已批准计划转为待复核。
    """
    return service.create_window(
        body.domain, body.certificate_fingerprint, body.role, body.start, body.end
    )


@app.get(f"{API}/service-windows", tags=["service-windows"])
def list_service_windows(domain: str | None = Query(default=None)):
    return {"items": service.list_windows(domain)}


@app.delete(f"{API}/service-windows/{{window_id}}", tags=["service-windows"])
def delete_service_window(window_id: int):
    return service.delete_window(window_id)


# ----------------------------- 计划 / 评估 / 批准 -----------------------------

@app.post(f"{API}/plans", status_code=201, tags=["plans"])
def create_plan(body: PlanCreate):
    """创建换发计划并立即评估：评估区间内每一时刻至少一张证书
    处于服务窗口且通过 X.509 校验。返回全部断档区间与各证书不可用原因。
    """
    return service.create_plan(
        body.domain, body.eval_start, body.eval_end, body.trust_root_version
    )


@app.get(f"{API}/plans", tags=["plans"])
def list_plans(
    domain: str | None = Query(default=None),
    status: str | None = Query(default=None),
):
    return {"items": service.list_plans(domain, status)}


@app.get(f"{API}/plans/{{plan_id}}", tags=["plans"])
def get_plan(plan_id: int):
    return service.get_plan(plan_id)


@app.post(f"{API}/plans/{{plan_id}}/evaluate", tags=["plans"])
def evaluate_plan(plan_id: int, body: EvaluateRequest | None = None):
    """重新评估计划，可指定切换信任根版本。"""
    version = body.trust_root_version if body else None
    return service.evaluate_plan(plan_id, version)


@app.post(f"{API}/plans/{{plan_id}}/approve", tags=["plans"])
def approve_plan(plan_id: int):
    """批准计划（仅无断档）。批准时冻结证书指纹、信任根版本与判定。"""
    return service.approve_plan(plan_id)


@app.get(f"{API}/plans/{{plan_id}}/evaluations", tags=["plans"])
def plan_evaluations(plan_id: int):
    """评估历史（全部保留）。"""
    return {"items": service.list_evaluations(plan_id)}


@app.get(f"{API}/plans/{{plan_id}}/approvals", tags=["plans"])
def plan_approvals(plan_id: int):
    """批准历史（含被取代的冻结判定，全部保留）。"""
    return {"items": service.list_approvals(plan_id)}
