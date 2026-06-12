"""Jenkins parser — reads declarative Jenkinsfile pipelines.

Jenkinsfiles are Groovy, not structured data, so this parser uses targeted
regexes/brace-matching rather than a full Groovy AST. It focuses on the
signals that matter for security/cost analysis: what kind of agent runs the
build (static node/label, or dynamic Docker/Kubernetes/cloud-fleet agents),
whether credentials are referenced via the credential store vs. hardcoded,
and whether the pipeline builds pull requests.
"""

from __future__ import annotations
import re
from pathlib import Path

from .base import BaseParser
from ..models.architecture import ArchitectureModel, Component, ComponentType

# Cloud-fleet-style agent labels (EC2 Fleet / Azure VM Agents / GKE node pools, ...)
_CLOUD_LABEL_RE = re.compile(r"(ec2|fleet|spot|azure.?vm|vmss|gke|autoscal)", re.I)

_AGENT_RE = re.compile(r"\bagent\s+(any|none|\{)")

_SENSITIVE_VAR_RE = re.compile(
    r"(\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|CREDENTIALS|PASSWD)\w*)\s*=\s*(['\"])(.*?)\2",
    re.I,
)

_TRIGGER_KEYWORDS = ("cron", "pollSCM", "githubPush", "gitlabPush", "bitbucketPush", "upstream", "GenericTrigger")


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _extract_block(content: str, keyword: str) -> str:
    m = re.search(rf"\b{keyword}\s*\{{", content)
    if not m:
        return ""
    open_idx = m.end() - 1
    close_idx = _find_matching_brace(content, open_idx)
    if close_idx == -1:
        return ""
    return content[open_idx + 1:close_idx]


def _classify_agent_block(block: str) -> str:
    if re.search(r"\bkubernetes\b", block):
        return "kubernetes"
    if re.search(r"\bdockerfile\b", block):
        return "dockerfile"
    if re.search(r"\bdocker\b", block):
        return "docker"
    m = re.search(r"\blabel\s*[:(]?\s*['\"]([^'\"]+)['\"]", block)
    if m:
        label = m.group(1)
        if _CLOUD_LABEL_RE.search(label):
            return f"cloud-label:{label}"
        return f"label:{label}"
    if re.search(r"\bnode\s*\{", block) or re.search(r"\bnode\s*\(", block):
        return "node"
    return "other"


def _find_agents(content: str) -> list[str]:
    agents = []
    for m in _AGENT_RE.finditer(content):
        kind = m.group(1)
        if kind in ("any", "none"):
            agents.append(kind)
            continue
        open_idx = m.end() - 1
        close_idx = _find_matching_brace(content, open_idx)
        block = content[open_idx:close_idx + 1] if close_idx != -1 else content[open_idx:open_idx + 300]
        agents.append(_classify_agent_block(block))
    return agents


def _find_hardcoded_secrets(content: str) -> list[str]:
    found: list[str] = []
    for env_block in re.findall(r"\benvironment\s*\{(.*?)\}", content, re.S):
        for var_name, _, value in _SENSITIVE_VAR_RE.findall(env_block):
            if value.startswith("$"):
                continue
            found.append(var_name)
    return found


class JenkinsParser(BaseParser):
    def can_parse(self, source: str | Path) -> bool:
        p = Path(source)
        if p.is_dir():
            return (p / "Jenkinsfile").exists()
        if not p.is_file():
            return False
        name = p.name.lower()
        if name == "jenkinsfile" or name.endswith(".jenkinsfile"):
            return True
        if p.suffix.lower() not in ("", ".groovy", ".jenkinsfile"):
            return False
        try:
            content = p.read_text(encoding="utf-8")
        except Exception:
            return False
        return bool(re.search(r"\bpipeline\s*\{", content)) and "agent" in content and "stages" in content

    def parse(self, source: str | Path) -> ArchitectureModel:
        p = Path(source)
        model = ArchitectureModel(name=p.name, source="jenkins")

        jenkins_files: list[Path] = []
        if p.is_dir():
            jf = p / "Jenkinsfile"
            if jf.exists():
                jenkins_files = [jf]
        else:
            jenkins_files = [p]

        for jf in jenkins_files:
            try:
                content = jf.read_text(encoding="utf-8")
                model.components.append(self._parse_pipeline(jf.stem or jf.name, content))
            except Exception:
                continue

        return model

    def _parse_pipeline(self, name: str, content: str) -> Component:
        agents = _find_agents(content)
        primary_agent = agents[0] if agents else "unspecified"
        agent_types = sorted(set(agents))

        is_dynamic_agent = any(
            a in ("kubernetes", "docker", "dockerfile") or a.startswith("cloud-label:")
            for a in agents
        )
        has_static_agent = any(
            a in ("any", "node") or (a.startswith("label:")) for a in agents
        )

        cred_ids = set(re.findall(r"credentials(?:Id)?\s*[:(]\s*['\"]([^'\"]+)['\"]", content))
        hardcoded_secrets = _find_hardcoded_secrets(content)

        stage_names = re.findall(r"\bstage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", content)

        trigger_block = _extract_block(content, "triggers")
        triggers = [kw for kw in _TRIGGER_KEYWORDS if re.search(rf"\b{kw}\b", trigger_block, re.I)]

        triggered_by_pr = bool(re.search(r"\bchangeRequest\s*\(", content))
        has_shell_steps = bool(re.search(r"\b(sh|bat|powershell)\s*[\('\"]", content))
        has_script_block = bool(re.search(r"\bscript\s*\{", content))

        return Component(
            id=f"jenkins.pipeline.{name}",
            name=name,
            type=ComponentType.OTHER,
            provider="generic",
            service="jenkins_pipeline",
            properties={
                "agent_types": agent_types,
                "primary_agent": primary_agent,
                "is_dynamic_agent": is_dynamic_agent,
                "has_static_agent": has_static_agent,
                "stage_count": len(stage_names),
                "stages": stage_names[:20],
                "credential_ids": sorted(cred_ids),
                "hardcoded_secrets_in_env": hardcoded_secrets,
                "triggers": triggers,
                "triggered_by_pr": triggered_by_pr,
                "has_shell_steps": has_shell_steps,
                "has_script_block": has_script_block,
            },
        )
