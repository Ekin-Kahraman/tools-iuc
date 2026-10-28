"""Inspect actual Planemo reports and preserve only synthetic validation evidence."""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.metadata
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import uuid

SOURCE_SHA = "3a4f2bf02924230c8d52b81665df224fa0c670b7"
GALAXY_SHA = "04fe1e82c16e3c3f7ab51ba50912d945cd9b0c36"
TOOL = Path("tools/rustscenic/rustscenic_grn.xml")
FIXTURES = {
    "expression.tsv": "541d075d2d848e75c996feda73b68eb5957714b31928a4299f16b9c623c805bb",
    "expression.csv": "90e1344d3045c5737a800308eccb974238d8ca4121df3bf26f2e48cdc6a78cb4",
    "expression.h5ad": "708479f983ea07728993dde5e1ca81ab5950b49232a594f0022835bd70144f12",
    "expression_transposed.tsv": "d4c17f123dbda3eb8c001e51b17d2e348eef199e53d1a980fc4305ec00d6d2eb",
    "tfs.txt": "6103ab81e0267084fdd733cad95d7d5b728f043fb75f0e4a7e6a3004c26e1ea4",
    "missing_tfs.txt": "429f5bba3c4bbb4656cac07a256f26803308a29cfd6ff93dc3c1d212c8bd6e42",
}
CREDENTIAL_PATTERNS = [
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    re.compile(r"authorization\s*[:=]\s*[\"']?\s*(?:bearer|token)\s+[A-Za-z0-9_.+/=-]{12,}", re.I),
    re.compile(r"[\"']?(?:master_api_key|admin_api_key|api_key|access_token|client_secret|password)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_./+%=-]{16,}", re.I),
    re.compile(r"--(?:galaxy_admin_key|galaxy_user_key|api-key|token)\s+[\"']?[A-Za-z0-9_./+%=-]{16,}", re.I),
    re.compile(r"[?&](?:X-Amz-Signature|access_token|api_key|token)=[A-Za-z0-9%_+.=-]{16,}", re.I),
    re.compile(r"https?://[^/\s:@]+:[^/\s@]{8,}@", re.I),
]


def credential_material(text):
    return any(pattern.search(text) for pattern in CREDENTIAL_PATTERNS)



def digest(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def preflight(artifact, phase="before"):
    subprocess.run(["git", "cat-file", "-e", SOURCE_SHA + "^{commit}"], check=True)
    subprocess.run(["git", "diff", "--exit-code", SOURCE_SHA, "HEAD", "--", str(TOOL.parent)], check=True)
    subprocess.run(["git", "diff", "--exit-code", SOURCE_SHA, "--", str(TOOL.parent)], check=True)
    assert not subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "--", str(TOOL.parent)], text=True).strip(), "Untracked wrapper files"
    source = ET.parse(TOOL).getroot()
    tests = source.findall("tests/test")
    assert len(tests) == 6, len(tests)
    assert [test.find("conditional/param[@name='format']").get("value") for test in tests[:3]] == ["tsv", "csv", "h5ad"]
    assert all(tests[i].get("expect_failure") == "true" and tests[i].get("expect_exit_code") == "2" for i in (4, 5))
    assert tests[5].find("conditional/param[@name='expression']").get("value") == "expression_transposed.tsv"
    assert source.find("macros/token[@name='@TOOL_VERSION@']").text == "0.5.1"
    hashes = {}
    for name, expected in FIXTURES.items():
        actual = digest((TOOL.parent / "test-data" / name).read_bytes())
        assert actual == expected, (name, actual)
        hashes[name] = actual
    tracked = subprocess.check_output(["git", "ls-files", "-z", "--", str(TOOL.parent)]).decode().split("\0")
    proof = {"phase": phase, "source_sha": SOURCE_SHA, "validation_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "galaxy_sha": GALAXY_SHA, "tool_sha256": digest(TOOL.read_bytes()), "tracked_wrapper_sha256": {name: digest(Path(name).read_bytes()) for name in tracked if name}, "fixture_sha256": hashes, "auditor_sha256": digest(Path(__file__).read_bytes()), "expected_tests_slots2": 6, "expected_tests_slots1": 1, "native_platform": platform.platform(), "native_machine": platform.machine(), "working_tree_matches_reviewed_source": True}
    if phase == "after":
        before = json.loads((artifact / "source-before.json").read_text())
        assert {k: v for k, v in proof.items() if k != "phase"} == {k: v for k, v in before.items() if k != "phase"}, "Source or fixtures changed during validation"
        proof["matches_before"] = True
    dump(artifact / f"source-{phase}.json", proof)


def collect_one(artifact, run, data_dir, temp_dir):
    collected = []
    for path in data_dir.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 2_000_000:
            continue
        raw = path.read_bytes()
        kind = "input" if digest(raw) in FIXTURES.values() else None
        if raw.startswith(b"TF\ttarget\timportance\n"):
            kind = "network"
        if raw.lstrip().startswith(b"{"):
            try:
                value = json.loads(raw)
                if value.get("stage") == "grn" and value.get("rustscenic_version") == "0.5.1":
                    kind = "fitting_metadata"
            except (ValueError, AttributeError):
                pass
        if kind:
            target = artifact / "datasets" / run / path.relative_to(data_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            collected.append({"kind": kind, "path": str(target.relative_to(artifact)), "sha256": digest(raw)})
    selected_jobs = set()
    for path in temp_dir.rglob("*.sh"):
        if "job_working_directory" not in path.parts or path.stat().st_size > 2_000_000:
            continue
        text = path.read_text(errors="replace")
        if "rustscenic grn" in text:
            enclosing_job = None
            for parent in path.parents:
                if "job_working_directory" not in parent.parts:
                    break
                if list(parent.glob("galaxy_*.sh")):
                    enclosing_job = parent
                    break
            assert enclosing_job is not None, "No enclosing Galaxy job script for " + str(path)
            selected_jobs.add(enclosing_job)
    for job in selected_jobs:
        for path in job.rglob("*.sh"):
            if path.name != "tool_script.sh" and not re.fullmatch(r"galaxy_[A-Za-z0-9_.-]+\.sh", path.name):
                continue
            text = path.read_text(errors="strict")
            assert not credential_material(text), "Do not upload potential credential material: " + str(path)
            target = artifact / "job-scripts" / run / path.relative_to(temp_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            collected.append({"kind": "job_script", "job_group": str(job.relative_to(temp_dir)), "path": str(target.relative_to(artifact)), "sha256": digest(path.read_bytes())})
    return collected


def collect(artifact, workspace):
    inventory = []
    for slots in (2, 1):
        inventory.extend(collect_one(artifact, f"slots{slots}", workspace / f"slots{slots}" / "objects", workspace / f"slots{slots}" / "tmp"))
    selected_packages = []
    dependency_python = []
    conda = Path(os.environ["CONDA"])
    for path in conda.glob("envs/*/conda-meta/rustscenic-*.json"):
        record = json.loads(path.read_text())
        selected_packages.append({key: record.get(key) for key in ("name", "version", "build", "subdir", "channel", "url", "sha256")})
        for python_record_path in path.parent.glob("python-*.json"):
            python_record = json.loads(python_record_path.read_text())
            if python_record.get("name") == "python":
                dependency_python.append({key: python_record.get(key) for key in ("name", "version", "build", "subdir", "url", "sha256")})
    dump(artifact / "collected-evidence.json", {"inventory": inventory, "rustscenic_conda_packages": selected_packages, "tool_dependency_python": dependency_python, "conda_version": subprocess.check_output([str(conda / "bin" / "conda"), "--version"], text=True).strip(), "selected_versions": {name: importlib.metadata.version(name) for name in ("planemo", "galaxy-tool-util", "galaxy-util")}, "python": sys.version})


def read_report(path, expected):
    report = json.loads(path.read_text())
    assert report.get("exit_code") in (None, 0), report.get("exit_code")
    tests, summary = report["tests"], report["summary"]
    assert len(tests) == expected and summary["num_tests"] == expected, summary
    assert all(summary[key] == 0 for key in ("num_failures", "num_errors", "num_skips")), summary
    assert all(case["data"]["status"] == "success" for case in tests), tests
    return {case["data"]["test_index"]: case["data"] for case in tests}


def canonical_network(path):
    rows = list(csv.DictReader(io.StringIO(path.read_text()), delimiter="\t"))
    assert rows and set(rows[0]) == {"TF", "target", "importance"}
    result = []
    for row in rows:
        tf, target, importance = row["TF"], row["target"], float(row["importance"])
        assert tf in {"TF_A", "TF_B"} and target in {"TF_A", "TF_B", "G1", "G2", "G3"}
        assert tf != target and math.isfinite(importance) and importance > 0
        result.append((tf, target, importance))
    assert ("TF_A", "G1") in {(x[0], x[1]) for x in result}
    assert ("TF_B", "G2") in {(x[0], x[1]) for x in result}
    return tuple(sorted(result))


def audit(artifact):
    before = json.loads((artifact / "source-before.json").read_text())
    after = json.loads((artifact / "source-after.json").read_text())
    assert before["phase"] == "before" and after["phase"] == "after" and after["matches_before"] is True
    assert before["tracked_wrapper_sha256"] == after["tracked_wrapper_sha256"] and before["fixture_sha256"] == after["fixture_sha256"]
    full = read_report(artifact / "slots2" / "galaxy-tests.json", 6)
    repeat = read_report(artifact / "slots1" / "galaxy-tests.json", 1)
    assert set(full) == set(range(6)) and set(repeat) == {0}
    for index, extension in enumerate(("tsv", "csv", "h5ad", "h5ad", "tsv", "tsv")):
        job = full[index]["job"]
        assert f"expression.{extension}" in job["command_line"], job["command_line"]
        assert int(job["exit_code"]) == (2 if index in (4, 5) else 0)
    assert all("error: no TFs" in full[index]["job"]["stderr"] for index in (4, 5))
    evidence = json.loads((artifact / "collected-evidence.json").read_text())
    assert evidence["rustscenic_conda_packages"], "No actual Conda dependency found"
    assert all(p["version"] == "0.5.1" and p["subdir"] == "linux-64" and "bioconda" in p["url"] and p["build"] == "py313hfa8f182_0" and p["sha256"] == "c5985afe2a9de78b2f250ea516950d09f50ab211696c74e312a5c0559d807c98" for p in evidence["rustscenic_conda_packages"])
    assert evidence["tool_dependency_python"] and all(p["version"].startswith("3.13.") for p in evidence["tool_dependency_python"])
    def dataset_for_case(run, case, name, kind):
        dataset_uuid = uuid.UUID(case["job"]["outputs"][name]["uuid"]).hex
        matches = [item for item in evidence["inventory"] if item["kind"] == kind
                   and "/" + run + "/" in item["path"]
                   and Path(item["path"]).stem.removeprefix("dataset_").replace("-", "").lower() == dataset_uuid]
        assert len(matches) == 1, (run, name, dataset_uuid, matches)
        return artifact / matches[0]["path"]

    canonical = {}
    metadata = {}
    resource_mapping = {}
    associations = []
    for slots, cases in ((2, full), (1, repeat)):
        run = f"slots{slots}"
        networks, fitting = {}, {}
        for index in (range(4) if slots == 2 else (0,)):
            case = cases[index]
            network_path = dataset_for_case(run, case, "network", "network")
            provenance_path = dataset_for_case(run, case, "provenance", "fitting_metadata")
            networks[index] = canonical_network(network_path)
            value = json.loads(provenance_path.read_text())
            assert (value["n_cells"], value["n_genes"], value["n_tfs_used"], value["seed"]) == (64, 5, 2, 777)
            fit = value["grn_fit"]
            assert fit["seed"] == 777 and fit["max_features"] == 1.0 and fit["subsample"] == 1.0 and fit["max_depth"] == 2
            if index < 3:
                assert fit["early_stop_mode"] == "arboreto"
                assert (fit["n_estimators_ceiling"], fit["early_stop_window"], fit["learning_rate"]) == (32, 0, 0.1)
            else:
                assert slots == 2 and fit["early_stop_mode"] == "legacy_inbag"
                assert (fit["n_estimators_ceiling"], fit["early_stop_window"], fit["learning_rate"]) == (16, 3, 0.2)
            fitting[index] = {key: item for key, item in value.items() if key != "wall_clock_s"}
            associations.append({"run": run, "test_index": index,
                                 "network": str(network_path.relative_to(artifact)),
                                 "provenance": str(provenance_path.relative_to(artifact)),
                                 "network_sha256": digest(network_path.read_bytes()),
                                 "provenance_sha256": digest(provenance_path.read_bytes())})
        if slots == 2:
            assert networks[0] == networks[1] == networks[2], "Actual format outputs differ"
            assert fitting[0] == fitting[1] == fitting[2], "Actual format fit telemetry differs"
        canonical[run], metadata[run] = networks[0], fitting[0]
        items = [item for item in evidence["inventory"] if "/" + run + "/" in item["path"]]
        groups = {}
        for item in items:
            if item["kind"] == "job_script":
                groups.setdefault(item["job_group"], []).append(item)
        assert len(groups) == (6 if slots == 2 else 1), (run, list(groups))
        for group, group_items in groups.items():
            scripts = "\n".join((artifact / item["path"]).read_text() for item in group_items)
            assert "rustscenic grn" in scripts, group
            assert f'GALAXY_SLOTS="{slots}"' in scripts, group
            assert 'RAYON_NUM_THREADS="${GALAXY_SLOTS:-1}"' in scripts, group
            assert all(f"{name}=1" in scripts for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "BLIS_NUM_THREADS", "NUMEXPR_NUM_THREADS")), group
        resource_mapping[run] = {"verified_job_groups": sorted(groups), "scope": "Each retained job-folder script pair configures Galaxy slots and maps Rayon; numerical-library env caps are one. No process/thread-count measurement."}
    assert canonical["slots2"] == canonical["slots1"], "Slot-count change altered actual edges"
    assert metadata["slots2"] == metadata["slots1"], "Slot-count change altered fit telemetry"
    dump(artifact / "verified-results.json", {"state": "PASS", "actual_planemo_tests": 7, "main_tests": 6, "resource_repeat_tests": 1, "failures": 0, "errors": 0, "skips": 0, "format_equivalence": "Per-test UUID-linked TSV/CSV/sparse-H5AD outputs exactly equal after row canonicalization", "slot_equivalence": "Actual UUID-linked one-slot/two-slot baseline edges and fit metadata exactly equal, excluding wall_clock_s", "per_test_output_associations": associations, "resource_mapping": resource_mapping, "method_scope": "Synthetic Galaxy plumbing and runtime validation only; no biological, scientific-parity or performance validation"})


def scan(artifact):
    allowed = {"slots1", "slots2", "datasets", "job-scripts", "source-before.json", "source-after.json", "collected-evidence.json", "verified-results.json", "lint.log", "planemo-test-help.txt", "planemo-lint-help.txt", "credential-scan.json"}
    text_count = binary_count = total_bytes = 0
    for path in artifact.rglob("*"):
        assert not path.is_symlink(), "Do not upload artifact symlinks"
        if not path.is_file():
            continue
        rel = path.relative_to(artifact)
        assert rel.parts[0] in allowed, "Unapproved artifact path: " + str(rel)
        raw = path.read_bytes()
        total_bytes += len(raw)
        if raw.startswith(b"\x89HDF\r\n\x1a\n"):
            assert digest(raw) == FIXTURES["expression.h5ad"], "Unexpected binary artifact: " + str(rel)
            binary_count += 1
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise AssertionError("Unapproved binary artifact: " + str(rel)) from None
        assert not credential_material(text), "Potential credential material detected; upload rejected for: " + str(rel)
        text_count += 1
    dump(artifact / "credential-scan.json", {"state": "PASS_PATTERN_SCAN_ONLY", "text_artifacts_scanned": text_count, "binary_synthetic_fixtures_verified_by_sha256": binary_count, "bytes_read": total_bytes, "scope": "Every existing whitelisted UTF-8 report, HTML, XML, log, command script and synthetic text dataset checked for known GitHub/AWS/private-key prefixes and value-bearing authorization/API-key/password/token/credential-URL patterns. Exact-hash H5AD fixtures preserved without text decoding. No whole-runtime, config, .git, environment-variable dump or credential-store upload. This is the stated pattern scan, not an absolute claim of no credentials anywhere."})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["preflight", "collect", "audit", "scan"])
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--phase", choices=["before", "after"], default="before")
    args = parser.parse_args()
    if args.mode == "preflight":
        preflight(args.artifact, args.phase)
    elif args.mode == "collect":
        collect(args.artifact, args.workspace)
    elif args.mode == "audit":
        audit(args.artifact)
    else:
        scan(args.artifact)
