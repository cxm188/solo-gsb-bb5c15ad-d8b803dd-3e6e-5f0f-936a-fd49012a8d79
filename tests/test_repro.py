"""审计复现包导出/核验的自测（无测试框架依赖）：python -m tests.test_repro

使用独立临时 SQLite 库，不触碰 ./data；只依赖 analyzer/database/repro，
无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from app import analyzer, database, repro

# 隔离的临时数据库（database.connect 在调用时读取 DB_PATH，运行时替换即可）
_TMP_DIR = tempfile.mkdtemp(prefix="repro-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _manifest() -> dict:
    # app(GPL-3.0) -> lib(Proprietary) 为硬冲突，保证结果里有可比对的内容
    return {
        "name": "repro-demo",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-3.0",
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": "Proprietary"},
        ],
    }


def _save(manifest: dict = None):
    manifest = manifest if manifest is not None else _manifest()
    result = analyzer.analyze_manifest(manifest)
    audit_id = database.save_audit(result, manifest)
    result["audit_id"] = audit_id
    return audit_id, result


def _export(audit_id: int) -> dict:
    bundle = database.get_audit_bundle(audit_id)
    return repro.build_package(bundle["name"], bundle["manifest"], bundle["result"])


def _check_entry(report: dict, key: str) -> dict:
    return next(c for c in report["checks"] if c["key"] == key)


def test_export_contains_digests_and_raw_result() -> None:
    audit_id, _ = _save()
    bundle = database.get_audit_bundle(audit_id)
    _check("bundle carries raw manifest", bundle["manifest"] == _manifest())
    package = repro.build_package(bundle["name"], bundle["manifest"], bundle["result"])
    _check("format version", package["format"] == repro.FORMAT)
    _check("audit name", package["audit_name"] == "repro-demo")
    _check("manifest digest",
           package["digests"]["manifest_sha256"] == repro.sha256_hex(bundle["manifest"]))
    _check("result digest",
           package["digests"]["result_sha256"] == repro.sha256_hex(bundle["result"]))
    _check("digests are sha256 hex",
           all(len(v) == 64 and all(c in "0123456789abcdef" for c in v)
               for v in package["digests"].values()))
    # 保存结果原样入包（含运行元数据），且不附着实时复核标记
    _check("result keeps audit_id", package["result"]["audit_id"] == audit_id)
    _check("result keeps created_at", bool(package["result"].get("created_at")))
    _check("no review attached",
           all("review" not in c for c in package["result"]["conflicts"]))
    _check("summary has no review", "review" not in package["result"]["summary"])
    # 包可整体序列化为可转交的单一 JSON
    json.dumps(package, ensure_ascii=False)


def test_roundtrip_passes() -> None:
    audit_id, _ = _save()
    report = repro.verify_package(_export(audit_id))
    _check("passed", report["passed"] is True, json.dumps(report, ensure_ascii=False))
    _check("read only flag", report["read_only"] is True)
    _check("all checks ok", all(c["ok"] for c in report["checks"]))
    _check("no mismatch", report["first_mismatch"] is None)
    _check("audit name", report["audit_name"] == "repro-demo")
    keys = [c["key"] for c in report["checks"]]
    _check("check order",
           keys == ["format", "manifest_digest", "result_digest", "recompute"], str(keys))


def test_digest_stable_under_key_reorder() -> None:
    audit_id, _ = _save()
    package = _export(audit_id)
    # 模拟转交途中被重新序列化（键顺序变化）：摘要不变、核验仍通过
    shuffled = json.loads(json.dumps(package, sort_keys=True))
    _check("shuffled package passes", repro.verify_package(shuffled)["passed"] is True)
    reversed_manifest = dict(reversed(list(package["manifest"].items())))
    _check("digest independent of key order",
           repro.sha256_hex(reversed_manifest) == package["digests"]["manifest_sha256"])


def test_tampered_manifest_fails_digest() -> None:
    audit_id, _ = _save()
    package = _export(audit_id)
    package["manifest"]["packages"][1]["license"] = "MIT"  # 篡改包内 manifest
    report = repro.verify_package(package)
    _check("not passed", report["passed"] is False)
    _check("manifest digest mismatch", _check_entry(report, "manifest_digest")["ok"] is False)
    _check("result digest still ok", _check_entry(report, "result_digest")["ok"] is True)
    # manifest 被改后复算结果也会偏离保存结果（lib 许可证变化 -> 冲突消失）
    _check("recompute mismatch reported", report["first_mismatch"] is not None)


def test_tampered_result_reports_first_mismatch() -> None:
    audit_id, _ = _save()
    package = _export(audit_id)
    package["result"]["conflicts"][0]["severity"] = "warning"  # 篡改保存结果
    report = repro.verify_package(package)
    _check("not passed", report["passed"] is False)
    _check("result digest mismatch", _check_entry(report, "result_digest")["ok"] is False)
    mismatch = report["first_mismatch"]
    _check("mismatch at severity", mismatch["path"] == "conflicts[0].severity", str(mismatch))
    _check("mismatch section", mismatch["section"] == "conflicts")
    _check("expected from package", mismatch["expected"] == "warning")
    _check("actual from recompute", mismatch["actual"] == "error")
    _check("message names the field", "conflicts[0].severity" in mismatch["message"])


def test_tampered_path_reports_first_mismatch() -> None:
    audit_id, _ = _save()
    package = _export(audit_id)
    package["result"]["conflicts"][0]["path"] = ["app@1", "ghost@9"]  # 篡改最短路径
    report = repro.verify_package(package)
    mismatch = report["first_mismatch"]
    _check("not passed", report["passed"] is False)
    _check("mismatch at path", mismatch["path"] == "conflicts[0].path[1]", str(mismatch))
    _check("mismatch section", mismatch["section"] == "conflicts")
    _check("expected from package", mismatch["expected"] == "ghost@9")
    _check("actual from recompute", mismatch["actual"] == "lib@1")


def test_node_count_mismatch_reported() -> None:
    audit_id, _ = _save()
    package = _export(audit_id)
    package["result"]["nodes"].append(dict(package["result"]["nodes"][0]))  # 多出一个节点
    report = repro.verify_package(package)
    mismatch = report["first_mismatch"]
    _check("not passed", report["passed"] is False)
    _check("length mismatch at nodes",
           mismatch["kind"] == "length" and mismatch["path"] == "nodes", str(mismatch))
    _check("length counts", mismatch["expected"] == 3 and mismatch["actual"] == 2)


def test_runtime_metadata_stripped_before_compare() -> None:
    audit_id, _ = _save()
    package = _export(audit_id)
    # 复算结果没有 audit_id / created_at，保存结果有；剔除后逐项一致
    stripped = repro._strip_runtime_meta(package["result"])
    _check("audit_id stripped", "audit_id" not in stripped)
    _check("created_at stripped", "created_at" not in stripped)
    recomputed = analyzer.analyze_manifest(package["manifest"], package["audit_name"])
    _check("stripped equals recomputed",
           repro._first_difference(stripped, repro._strip_runtime_meta(recomputed)) is None)
    # 但摘要覆盖完整保存结果：篡改 created_at 仍会被摘要检查发现
    package["result"]["created_at"] = "2000-01-01T00:00:00+00:00"
    report = repro.verify_package(package)
    _check("created_at tamper fails", report["passed"] is False)
    _check("result digest catches meta tamper",
           _check_entry(report, "result_digest")["ok"] is False)
    _check("compare unaffected (meta stripped)", report["first_mismatch"] is None)


def test_format_errors() -> None:
    audit_id, _ = _save()
    good = _export(audit_id)

    def expect_error(name: str, package, needle: str) -> None:
        try:
            repro.verify_package(package)
        except ValueError as exc:
            _check(name, needle in str(exc), str(exc))
            return
        raise AssertionError("%s 未抛出 ValueError" % name)

    expect_error("non-dict package", [1, 2], "JSON 对象")
    expect_error("wrong format version", dict(good, format="audit-repro/0"), "格式版本")
    expect_error("missing audit_name",
                 {k: v for k, v in good.items() if k != "audit_name"}, "audit_name")
    expect_error("missing digests",
                 {k: v for k, v in good.items() if k != "digests"}, "digests")
    bad_hex = copy.deepcopy(good)
    bad_hex["digests"]["manifest_sha256"] = "zz"
    expect_error("bad digest hex", bad_hex, "manifest_sha256")
    expect_error("manifest not object", dict(good, manifest="nope"), "manifest")
    expect_error("result not object", dict(good, result=None), "result")


def test_cyclonedx_roundtrip() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": "a", "name": "app", "version": "1",
             "licenses": [{"license": {"id": "GPL-3.0"}}]},
            {"bom-ref": "b", "name": "lib", "version": "2",
             "licenses": [{"expression": "Proprietary"}]},
        ],
        "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
    }
    audit_id, _ = _save(bom)
    package = _export(audit_id)
    _check("cyclonedx source format kept",
           package["result"].get("source_format") == "cyclonedx")
    report = repro.verify_package(package)
    _check("cyclonedx passes", report["passed"] is True,
           json.dumps(report, ensure_ascii=False))


def test_verify_is_read_only() -> None:
    audit_id, _ = _save()
    before = len(database.list_audits(100))
    repro.verify_package(_export(audit_id))
    _check("no new audit created", len(database.list_audits(100)) == before)
    _check("no review created", database.list_reviews(limit=500) == [])


def main() -> None:
    test_export_contains_digests_and_raw_result()
    test_roundtrip_passes()
    test_digest_stable_under_key_reorder()
    test_tampered_manifest_fails_digest()
    test_tampered_result_reports_first_mismatch()
    test_tampered_path_reports_first_mismatch()
    test_node_count_mismatch_reported()
    test_runtime_metadata_stripped_before_compare()
    test_format_errors()
    test_cyclonedx_roundtrip()
    test_verify_is_read_only()
    print("\nall repro tests passed.")


if __name__ == "__main__":
    main()
