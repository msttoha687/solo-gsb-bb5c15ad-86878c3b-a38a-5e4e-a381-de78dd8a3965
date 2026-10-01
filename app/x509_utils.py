"""X.509/PEM 处理与证书链静态校验（纯本地校验，不访问网络）。

校验内容：
  * PEM 解析（链中第一张为叶子证书，其余为中间 CA）
  * 签名链：逐跳验签直至指定版本的信任根（支持 AKI/SKI 匹配）
  * CA 约束：basicConstraints cA、keyUsage keyCertSign、pathLenConstraint
  * 叶子证书不得是 CA
  * 域名 SAN：DNSName 精确匹配或左标签单级通配符匹配
  * 证书有效期在评估时刻逐点检查（path_validity 给出整链有效期包络）
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .errors import ApiError, invalid_pem

_PEM_HEADER = b"-----BEGIN CERTIFICATE-----"


def parse_pem_chain(pem_text: str, *, what: str = "证书链") -> list[x509.Certificate]:
    """从 PEM 文本中解析出全部证书（至少一张）。

    允许文本中包含空白与非证书内容；PEM 块损坏、零张证书均拒绝。
    """
    if not isinstance(pem_text, str) or not pem_text.strip():
        raise invalid_pem(f"{what}为空：期望一个或多个 PEM 编码证书")
    try:
        raw = pem_text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise invalid_pem(f"{what}包含非 ASCII 字符，PEM 必须为 ASCII/Base64 编码") from exc

    if _PEM_HEADER not in raw:
        raise invalid_pem(f"{what}中未找到 {_PEM_HEADER.decode()} 标记")

    certs: list[x509.Certificate] = []
    # 逐块解析，单个坏块即可定位错误
    remaining = raw
    while True:
        idx = remaining.find(_PEM_HEADER)
        if idx < 0:
            break
        end = remaining.find(b"-----END CERTIFICATE-----", idx)
        if end < 0:
            raise invalid_pem(f"{what}存在缺少 END 标记的损坏 PEM 块")
        block = remaining[idx:end + len(b"-----END CERTIFICATE-----")]
        try:
            certs.append(x509.load_pem_x509_certificate(block))
        except Exception as exc:  # ValueError etc.
            raise invalid_pem(f"{what}包含无法解析的 PEM 证书块: {exc}") from exc
        remaining = remaining[end + len(b"-----END CERTIFICATE-----"):]

    if not certs:
        raise invalid_pem(f"{what}中没有任何证书")
    return certs


def to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def canonical_pem(certs: list[x509.Certificate]) -> str:
    return "".join(to_pem(c) for c in certs)


def fingerprint_hex(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _cn(name: x509.Name) -> str:
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def cert_meta(cert: x509.Certificate) -> dict:
    return {
        "subject_cn": _cn(cert.subject),
        "issuer_cn": _cn(cert.issuer),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
    }


# ---------------------------------------------------------------- 基础比对

def _names_equal(a: x509.Name, b: x509.Name) -> bool:
    return a.public_bytes() == b.public_bytes()


def _is_self_issued(cert: x509.Certificate) -> bool:
    return _names_equal(cert.subject, cert.issuer)


def _ski(cert: x509.Certificate) -> Optional[bytes]:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
    except x509.ExtensionNotFound:
        return None


def _aki(cert: x509.Certificate) -> Optional[x509.AuthorityKeyIdentifier]:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
    except x509.ExtensionNotFound:
        return None


def _aki_matches(child: x509.Certificate, candidate: x509.Certificate) -> bool:
    """AKI/SKI 仅作消歧：子证书带 AKI keyIdentifier 时，候选必须有匹配的 SKI。"""
    aki = _aki(child)
    if aki is None or aki.key_identifier is None:
        return True
    return _ski(candidate) == aki.key_identifier


def verify_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """验证 child 证书上的签名是否由 issuer 的公钥签发。"""
    pub = issuer.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if child.signature_hash_algorithm is None:
                return False
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            if child.signature_hash_algorithm is None:
                return False
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        elif isinstance(pub, dsa.DSAPublicKey):
            if child.signature_hash_algorithm is None:
                return False
            pub.verify(child.signature, child.tbs_certificate_bytes, child.signature_hash_algorithm)
        else:
            return False
        return True
    except Exception:  # 任何验签异常（含 InvalidSignature/不支持的算法）均视为不匹配
        return False


# ---------------------------------------------------------------- CA 约束

def is_ca(cert: x509.Certificate) -> bool:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        return bool(ext.ca)
    except x509.ExtensionNotFound:
        return False


def _ca_constraint_ok(cert: x509.Certificate, *, label: str) -> Optional[str]:
    """CA 证书必须 cA=TRUE；若含 keyUsage 必须置 keyCertSign。"""
    if not is_ca(cert):
        return f"{label} 不是 CA（basicConstraints.cA 未置位），不能签发证书"
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not ku.key_cert_sign:
            return f"{label} 的 keyUsage 未包含 keyCertSign"
    except x509.ExtensionNotFound:
        pass
    return None


def _path_len_ok(path: list[x509.Certificate]) -> Optional[str]:
    """pathLenConstraint：非信任锚 CA 下方非自签发中间 CA 数量不得超限。"""
    end = len(path) - 1
    for i in range(1, end):  # path[-1] 为信任根，其 pathLen 不约束本链
        ca = path[i]
        try:
            bc = ca.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        except x509.ExtensionNotFound:
            continue
        if bc.path_length is None:
            continue
        n_below = sum(1 for j in range(1, i) if not _is_self_issued(path[j]))
        if n_below > bc.path_length:
            return (
                f"中间 CA(CN={_cn(ca.subject)}) 的 pathLenConstraint={bc.path_length}，"
                f"但其下方存在 {n_below} 个非自签发中间 CA"
            )
    return None


# ---------------------------------------------------------------- SAN

def domain_matches_san(cert: x509.Certificate, domain: str) -> tuple[bool, str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return False, "叶子证书缺少 subjectAltName 扩展"
    dns_names = san.value.get_values_for_type(x509.DNSName)
    if not dns_names:
        return False, "叶子证书 SAN 中没有 dNSName"

    target = domain.strip(".").lower()
    for name in dns_names:
        n = name.strip(".").lower()
        if n == target:
            return True, ""
        if n.startswith("*."):
            suffix = n[2:]
            target_labels = target.split(".")
            # *.example.com 只匹配 a.example.com 这种恰好一级标签的名字
            if len(target_labels) >= 2 and ".".join(target_labels[1:]) == suffix:
                return True, ""
    return False, f"SAN {dns_names} 与域名 {domain} 不匹配"


# ---------------------------------------------------------------- 链路构建

@dataclass
class ChainResult:
    ok: bool
    errors: list[dict] = field(default_factory=list)
    path_fps: list[str] = field(default_factory=list)
    path_subjects: list[str] = field(default_factory=list)
    root_fp: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None


def _envelope(path: list[x509.Certificate]) -> tuple[datetime, datetime]:
    return (
        max(c.not_valid_before_utc for c in path),
        min(c.not_valid_after_utc for c in path),
    )


def verify_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    roots: list[x509.Certificate],
) -> ChainResult:
    """构建并静态验证到信任根的证书路径（有效期不在此处判定）。"""
    result = ChainResult(ok=False)

    if is_ca(leaf):
        result.errors.append({"code": "leaf_is_ca", "reason": "叶子证书带有 basicConstraints.cA=TRUE，不能作为终端实体证书"})
        return result

    roots_by_der = {r.public_bytes(serialization.Encoding.DER): r for r in roots}
    inter_by_der = {c.public_bytes(serialization.Encoding.DER): c for c in intermediates}

    def find_anchors(cert: x509.Certificate) -> list[x509.Certificate]:
        out = []
        for der, root in roots_by_der.items():
            if _names_equal(cert.issuer, root.subject) and _aki_matches(cert, root):
                out.append(root)
        return out

    def find_issuers(cert: x509.Certificate, pool: dict[bytes, x509.Certificate]) -> list[x509.Certificate]:
        out = []
        for der, cand in pool.items():
            if _names_equal(cert.issuer, cand.subject) and _aki_matches(cert, cand):
                out.append(cand)
        return out

    bad_signatures: list[str] = []

    def build(cert: x509.Certificate,
              path: list[x509.Certificate],
              pool: dict[bytes, x509.Certificate]) -> Optional[list[x509.Certificate]]:
        # 先尝试直接链到信任根
        for anchor in find_anchors(cert):
            if verify_signed_by(cert, anchor):
                return path + [anchor]
            bad_signatures.append(
                f"CN={_cn(cert.subject)} 指向信任根 CN={_cn(anchor.subject)}，但签名校验失败"
            )
        # 否则尝试中间 CA（排除已用证书以防环）
        for cand in find_issuers(cert, pool):
            if not verify_signed_by(cert, cand):
                bad_signatures.append(
                    f"CN={_cn(cert.subject)} 指向 CN={_cn(cand.subject)}，但签名校验失败"
                )
                continue
            next_pool = {k: v for k, v in pool.items()
                         if k != cand.public_bytes(serialization.Encoding.DER)}
            found = build(cand, path + [cand], next_pool)
            if found is not None:
                return found
        return None

    path = build(leaf, [leaf], inter_by_der)

    if path is None:
        if bad_signatures:
            result.errors.append({"code": "bad_signature", "reason": "；".join(dict.fromkeys(bad_signatures))})
        result.errors.append({
            "code": "no_trusted_path",
            "reason": "无法在指定信任根版本内构建到受信根的完整证书链"
                     "（缺中间证书、issuer/subject 不匹配或根不受信）",
        })
        nb, na = _envelope([leaf])
        result.not_before, result.not_after = nb, na
        return result

    # CA 约束复检（路径中的每一张 CA 证书）
    ca_errors: list[str] = []
    for idx in range(1, len(path)):
        label = "信任根" if idx == len(path) - 1 else "中间 CA"
        msg = _ca_constraint_ok(path[idx], label=f"{label}(CN={_cn(path[idx].subject)})")
        if msg:
            ca_errors.append(msg)
    if ca_errors:
        for e in ca_errors:
            result.errors.append({"code": "ca_constraint", "reason": e})
        nb, na = _envelope(path)
        result.not_before, result.not_after = nb, na
        return result

    plen_msg = _path_len_ok(path)
    if plen_msg:
        result.errors.append({"code": "path_len_exceeded", "reason": plen_msg})
        nb, na = _envelope(path)
        result.not_before, result.not_after = nb, na
        return result

    nb, na = _envelope(path)
    result.ok = True
    result.path_fps = [fingerprint_hex(c) for c in path]
    result.path_subjects = [_cn(c.subject) for c in path]
    result.root_fp = fingerprint_hex(path[-1])
    result.not_before, result.not_after = nb, na
    return result


def assert_root_bundle(certs: list[x509.Certificate]) -> None:
    """信任根导入时的额外要求：每张均须为自签名 CA，且自签名可验过。"""
    for c in certs:
        label = f"CN={_cn(c.subject)}"
        if not is_ca(c):
            raise ApiError(400, "invalid_trust_root", f"信任根 {label} 不是 CA（basicConstraints.cA 未置位）")
        if not _is_self_issued(c):
            raise ApiError(400, "invalid_trust_root", f"信任根 {label} 不是自签名证书")
        if not verify_signed_by(c, c):
            raise ApiError(400, "invalid_trust_root", f"信任根 {label} 自签名校验失败")
