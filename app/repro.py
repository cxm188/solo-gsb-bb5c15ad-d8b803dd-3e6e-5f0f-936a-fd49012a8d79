"""审计复现包：导出与离线核验（只读）。

复现包把一次历史审计的 **原始 manifest** 与 **未附着实时复核标记的保存结果**
（即 SQLite 中持久化的 result_json，不含 API 响应层才附着的 review 字段）
打包成可离线转交的单一 JSON::

    {
      "format": "audit-repro/1",             # 格式版本
      "audit_name": "billing-platform-demo", # 审计名称
      "digests": {                           # 稳定键序列化后的 SHA-256
        "manifest_sha256": "…",
        "result_sha256": "…"
      },
      "manifest": { … },                     # 原始 manifest（原生或 CycloneDX）
      "result": { … }                        # 保存的审计结果（含 audit_id / created_at）
    }

核验（上传复现包）按固定顺序执行，全部通过才判 ``passed = true``：

1. **结构校验** —— 格式版本与字段类型；格式错误抛出 ``ValueError``
   （API 层转为 422 并给出明确提示）；
2. **摘要重算** —— 对包内 manifest / result 按稳定键序列化
   （``json.dumps(sort_keys=True)`` 的紧凑 JSON）重算 SHA-256，
   与包内摘要逐一比对；
3. **复算比对** —— 用包内 manifest 调用 ``analyzer.analyze_manifest`` 重新分析，
   剔除 ``audit_id`` / ``created_at`` 等运行元数据（以及响应层附着的实时复核
   标记字段）后，按 节点 → 依赖边 → 冲突（严重程度、路径等）→ 其余小节 的顺序
   逐项深度比对，发现不一致时指出 **首个不一致字段**。

核验是纯内存只读计算：不创建审计、不改动复核标记、不访问数据库。
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from . import analyzer

FORMAT = "audit-repro/1"
KIND = "audit-repro-verification"

_DIGEST_FIELDS = ("manifest_sha256", "result_sha256")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# 比对前剔除的运行元数据：随每次审计/响应而变化，不属于可复现内容
_RUNTIME_META_KEYS = ("audit_id", "created_at", "filtered", "filter")

# 顶层小节的固定比对顺序：先节点与依赖边，再冲突（含严重程度与路径），最后其余
_SECTION_ORDER = (
    "manifest_name",
    "status",
    "summary",
    "nodes",
    "edges",
    "conflicts",
    "unresolved",
    "warnings",
)

_SECTION_LABELS = {
    "manifest_name": "审计名称",
    "status": "审计状态",
    "summary": "统计摘要",
    "nodes": "节点",
    "edges": "依赖边",
    "conflicts": "冲突/告警",
    "unresolved": "未解析依赖",
    "warnings": "告警信息",
}


# --- 稳定序列化与摘要 ---------------------------------------------------------


def canonical_json(value: Any) -> str:
    """稳定键序列化：对象键排序 + 紧凑分隔符，同一内容必然得到同一字符串。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(value: Any) -> str:
    """对任意 JSON 值先稳定键序列化再取 SHA-256（小写十六进制）。"""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# --- 导出 ---------------------------------------------------------------------


def build_package(audit_name: str, manifest: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    """把原始 manifest 与保存结果打包为复现包（摘要按包内容即时计算）。"""
    return {
        "format": FORMAT,
        "audit_name": str(audit_name),
        "digests": {
            "manifest_sha256": sha256_hex(manifest),
            "result_sha256": sha256_hex(result),
        },
        "manifest": manifest,
        "result": result,
    }


# --- 核验 ---------------------------------------------------------------------


def verify_package(package: Any) -> Dict[str, Any]:
    """核验复现包并返回报告；格式错误抛 ``ValueError``（API 层转为 422）。

    报告中的 ``checks`` 按 格式 → manifest 摘要 → 保存结果摘要 → 复算比对
    的顺序排列，``passed`` 仅在全部通过时为 ``True``。
    """
    audit_name, digests, manifest, result = _validate(package)

    checks: List[Dict[str, Any]] = [
        {"key": "format", "label": "格式版本", "ok": True, "detail": FORMAT}
    ]

    # 1) 摘要重算（稳定键序列化后的 SHA-256）
    manifest_digest = sha256_hex(manifest)
    result_digest = sha256_hex(result)
    checks.append(
        _digest_check("manifest_digest", "manifest 摘要", digests["manifest_sha256"], manifest_digest)
    )
    checks.append(
        _digest_check("result_digest", "保存结果摘要", digests["result_sha256"], result_digest)
    )

    # 2) 用包内 manifest 调用现有分析器复算（审计名称作为缺省名，保证可复现）
    recomputed = analyzer.analyze_manifest(manifest, audit_name)
    recompute_error = (
        str(recomputed.get("error")) if recomputed.get("status") == "error" else None
    )

    # 3) 剔除运行元数据后逐项比对，记录首个不一致字段
    mismatch: Optional[Dict[str, Any]] = None
    if recompute_error is None:
        expected = _strip_runtime_meta(result)
        actual = _strip_runtime_meta(recomputed)
        mismatch = _first_difference(expected, actual)

    recompute_ok = recompute_error is None and mismatch is None
    checks.append(
        {
            "key": "recompute",
            "label": "复算比对",
            "ok": recompute_ok,
            "detail": _recompute_detail(recomputed, recompute_error, mismatch),
        }
    )

    passed = all(c["ok"] for c in checks)
    return {
        "kind": KIND,
        "read_only": True,
        "passed": passed,
        "format": FORMAT,
        "audit_name": audit_name,
        "checks": checks,
        "first_mismatch": mismatch,
        "recomputed_summary": recomputed.get("summary"),
        "message": _final_message(passed, checks, mismatch, recompute_error),
    }


def _validate(package: Any) -> Tuple[str, Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """校验复现包结构，返回 (审计名称, 摘要, manifest, 保存结果)；格式错误抛 ValueError。"""
    if not isinstance(package, dict):
        raise ValueError(
            "复现包必须是 JSON 对象（含 format / audit_name / digests / manifest / result 字段）。"
        )
    fmt = package.get("format")
    if fmt != FORMAT:
        raise ValueError("复现包格式版本不支持：%r（本服务期望 %r）。" % (fmt, FORMAT))
    audit_name = package.get("audit_name")
    if not isinstance(audit_name, str) or not audit_name.strip():
        raise ValueError("复现包缺少有效的 audit_name（审计名称，非空字符串）。")
    digests = package.get("digests")
    if not isinstance(digests, dict):
        raise ValueError("复现包缺少 digests 对象（应包含 manifest_sha256 与 result_sha256）。")
    for field in _DIGEST_FIELDS:
        value = digests.get(field)
        if not isinstance(value, str) or not _SHA256_RE.match(value):
            raise ValueError(
                "digests.%s 缺失或不是 64 位小写十六进制 SHA-256 摘要：%r。" % (field, value)
            )
    manifest = package.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("复现包的 manifest 缺失或不是 JSON 对象。")
    result = package.get("result")
    if not isinstance(result, dict):
        raise ValueError("复现包的 result 缺失或不是 JSON 对象。")
    return audit_name.strip(), digests, manifest, result


def _digest_check(key: str, label: str, recorded: str, recomputed: str) -> Dict[str, Any]:
    ok = recorded == recomputed
    if ok:
        detail = "包内摘要与重算一致（%s…）" % recorded[:12]
    else:
        detail = "包内摘要 %s… ≠ 重算 %s…，内容可能被篡改或损坏" % (
            recorded[:12],
            recomputed[:12],
        )
    return {
        "key": key,
        "label": label,
        "ok": ok,
        "expected": recorded,
        "actual": recomputed,
        "detail": detail,
    }


def _recompute_detail(
    recomputed: Dict[str, Any],
    recompute_error: Optional[str],
    mismatch: Optional[Dict[str, Any]],
) -> str:
    if recompute_error is not None:
        return "包内 manifest 无法重新分析：%s" % recompute_error
    if mismatch is not None:
        return mismatch["message"]
    summary = recomputed.get("summary") or {}
    conflicts = int(summary.get("conflicts") or 0) + int(summary.get("license_warnings") or 0)
    return "复算结果与保存结果逐项一致（节点 %s、依赖边 %s、冲突/告警 %s）" % (
        summary.get("packages"),
        summary.get("edges"),
        conflicts,
    )


def _final_message(
    passed: bool,
    checks: List[Dict[str, Any]],
    mismatch: Optional[Dict[str, Any]],
    recompute_error: Optional[str],
) -> str:
    if passed:
        return "核验通过：两项 SHA-256 摘要一致，且复算结果与保存结果逐项一致。"
    parts: List[str] = []
    bad_digests = [c["label"] for c in checks if not c["ok"] and c["key"].endswith("_digest")]
    if bad_digests:
        parts.append("摘要不一致（%s）" % "、".join(bad_digests))
    if recompute_error is not None:
        parts.append("包内 manifest 无法重新分析")
    elif mismatch is not None:
        parts.append("首个不一致字段为 %s" % mismatch["path"])
    if not parts:
        parts.append("、".join(c["label"] for c in checks if not c["ok"]))
    return "核验未通过：%s。" % "；".join(parts)


# --- 运行元数据剔除与逐项比对 ---------------------------------------------------


def _strip_runtime_meta(result: Dict[str, Any]) -> Dict[str, Any]:
    """剔除运行元数据：审计 id、创建时间，以及响应层才附着的实时复核标记。"""
    cleaned = {k: v for k, v in result.items() if k not in _RUNTIME_META_KEYS}
    summary = cleaned.get("summary")
    if isinstance(summary, dict):
        summary = dict(summary)
        summary.pop("review", None)  # 复核计数只出现在 API 响应层
        cleaned["summary"] = summary
    conflicts = cleaned.get("conflicts")
    if isinstance(conflicts, list):
        cleaned["conflicts"] = [
            {k: v for k, v in c.items() if k != "review"} if isinstance(c, dict) else c
            for c in conflicts
        ]
    return cleaned


def _ordered_keys(expected: Dict[str, Any], actual: Dict[str, Any], top_level: bool) -> List[str]:
    keys = list(dict.fromkeys(list(expected) + list(actual)))
    if not top_level:
        return sorted(keys, key=str)
    rank = {name: index for index, name in enumerate(_SECTION_ORDER)}
    return sorted(keys, key=lambda k: (rank.get(k, len(_SECTION_ORDER)), str(k)))


def _first_difference(expected: Any, actual: Any, path: str = "") -> Optional[Dict[str, Any]]:
    """深度比对两个结果，返回首个不一致点（遍历顺序确定）；完全一致返回 None。"""
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in _ordered_keys(expected, actual, top_level=not path):
            child_path = "%s.%s" % (path, key) if path else str(key)
            if key not in expected:
                return _mismatch("extra", child_path, str(key), None, actual[key])
            if key not in actual:
                return _mismatch("missing", child_path, str(key), expected[key], None)
            found = _first_difference(expected[key], actual[key], child_path)
            if found is not None:
                return found
        return None
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return _mismatch("length", path, "length", len(expected), len(actual))
        for index, (exp_item, act_item) in enumerate(zip(expected, actual)):
            found = _first_difference(exp_item, act_item, "%s[%d]" % (path, index))
            if found is not None:
                return found
        return None
    if expected != actual:
        field = path.rsplit(".", 1)[-1] if path else "(根)"
        return _mismatch("value", path, field, expected, actual)
    return None


def _mismatch(kind: str, path: str, field: str, expected: Any, actual: Any) -> Dict[str, Any]:
    section = re.split(r"[.\[]", path, maxsplit=1)[0] if path else ""
    label = _SECTION_LABELS.get(section, section or "结果")
    shown_path = path or "(根)"
    if kind == "length":
        message = "首个不一致字段：%s —— %s数量不一致，保存结果 %s 项，复算结果 %s 项。" % (
            shown_path,
            label,
            expected,
            actual,
        )
    elif kind == "missing":
        message = "首个不一致字段：%s —— 保存结果存在该字段（%s），复算结果缺失。" % (
            shown_path,
            _short(expected),
        )
    elif kind == "extra":
        message = "首个不一致字段：%s —— 复算结果多出该字段（%s），保存结果中没有。" % (
            shown_path,
            _short(actual),
        )
    else:
        message = "首个不一致字段：%s —— 保存结果为 %s，复算结果为 %s。" % (
            shown_path,
            _short(expected),
            _short(actual),
        )
    return {
        "kind": kind,
        "section": section or None,
        "section_label": label,
        "path": shown_path,
        "field": field,
        "expected": expected,
        "actual": actual,
        "message": message,
    }


def _short(value: Any, limit: int = 120) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 1] + "…"
