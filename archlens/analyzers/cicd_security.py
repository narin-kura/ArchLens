"""CI/CD security analyzer — checks GitHub Actions, Jenkins, and Azure Pipelines
runner/agent configurations for risky dynamic vs. static compute setups."""

from __future__ import annotations

from .base import BaseAnalyzer
from ..models.architecture import ArchitectureModel
from ..models.findings import Finding, FindingType, Severity


class CicdSecurityAnalyzer(BaseAnalyzer):
    def analyze(self, model: ArchitectureModel) -> list[Finding]:
        findings: list[Finding] = []
        for check in [
            # GitHub Actions
            self._check_gha_self_hosted_pr_trigger,
            self._check_gha_self_hosted_ephemeral,
            self._check_gha_dynamic_runner_expression,
            # Jenkins
            self._check_jenkins_static_agent_pr_trigger,
            self._check_jenkins_hardcoded_secrets,
            self._check_jenkins_static_agent_isolation,
            # Azure Pipelines
            self._check_ado_self_hosted_pr_trigger,
            self._check_ado_persist_credentials,
            self._check_ado_hardcoded_secrets,
            self._check_ado_self_hosted_recommend_scale_set,
        ]:
            findings.extend(check(model))
        return findings

    # --------------------------------------------------------- GitHub Actions

    def _gha_workflows(self, model: ArchitectureModel) -> list:
        return [c for c in model.components if c.service == "github_actions_workflow"]

    def _check_gha_self_hosted_pr_trigger(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._gha_workflows(model):
            runner_types = c.properties.get("runner_types") or []
            if "self-hosted" in runner_types and c.properties.get("pr_trigger"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Workflow '{c.name}' runs self-hosted runners on pull_request events",
                    description="A self-hosted runner that builds pull_request-triggered jobs can execute arbitrary code from a fork PR on your infrastructure — a classic 'pwn request' RCE path.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Restrict this workflow to GitHub-hosted runners for pull_request triggers, or require approval for first-time contributors (Settings > Actions > Fork pull request workflows).",
                    references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#preventing-pwn-requests"],
                ))
        return findings

    def _check_gha_self_hosted_ephemeral(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._gha_workflows(model):
            runner_types = c.properties.get("runner_types") or []
            if "self-hosted" in runner_types:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Workflow '{c.name}' uses self-hosted runners — verify they are ephemeral",
                    description="The workflow YAML can't reveal whether these self-hosted runners are ephemeral. Persistent (non-ephemeral) runners retain disk state, cached credentials, and processes between jobs from different branches or PRs.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Use Actions Runner Controller (ARC) with ephemeral: true, or an autoscaling fleet that destroys the VM/container after each job.",
                    references=["https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners-with-actions-runner-controller/about-actions-runner-controller"],
                ))
        return findings

    def _check_gha_dynamic_runner_expression(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._gha_workflows(model):
            runner_types = c.properties.get("runner_types") or []
            if "dynamic-expression" in runner_types:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.INFO,
                    title=f"Workflow '{c.name}' computes its runner label with an expression",
                    description="`runs-on` is set via a ${{ }} expression, so whether the job lands on a hosted or self-hosted runner is resolved at run time and can't be verified statically.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Audit the expression's possible values to ensure pull_request-triggered jobs can never resolve to a privileged self-hosted pool.",
                    references=["https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idruns-on"],
                ))
        return findings

    # --------------------------------------------------------------- Jenkins

    def _jenkins_pipelines(self, model: ArchitectureModel) -> list:
        return [c for c in model.components if c.service == "jenkins_pipeline"]

    def _check_jenkins_static_agent_pr_trigger(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._jenkins_pipelines(model):
            if c.properties.get("has_static_agent") and c.properties.get("triggered_by_pr"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Pipeline '{c.name}' builds pull requests on a static agent",
                    description="A static agent (any/node/label) that builds changeRequest() (PR) branches executes code from forks or branches on persistent infrastructure — a classic RCE-via-PR path.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Run PR builds on ephemeral Kubernetes or Docker agents, or gate PR builds behind manual approval for external contributors.",
                    references=["https://www.jenkins.io/doc/book/security/securing-jenkins/"],
                ))
        return findings

    def _check_jenkins_hardcoded_secrets(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._jenkins_pipelines(model):
            secrets = c.properties.get("hardcoded_secrets_in_env") or []
            if secrets:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Pipeline '{c.name}' has hardcoded secrets in its environment block: {', '.join(secrets)}",
                    description="Literal credential values in a Jenkinsfile environment{} block are stored in plaintext in source control and visible to anyone with repo read access.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Use the Jenkins Credentials store with credentials() bindings instead of literal values.",
                    references=["https://www.jenkins.io/doc/book/using/using-credentials/"],
                ))
        return findings

    def _check_jenkins_static_agent_isolation(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._jenkins_pipelines(model):
            if c.properties.get("has_static_agent") and not c.properties.get("is_dynamic_agent"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Pipeline '{c.name}' runs on a static agent ({c.properties.get('primary_agent')})",
                    description="Static agents (any/node/label) are long-lived and shared across builds — workspace files, cached credentials, and tool state can leak between jobs from different branches or repos.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Move to `agent { kubernetes { ... } }` or `agent { docker { ... } }` so each build gets a clean, disposable agent.",
                    references=["https://www.jenkins.io/doc/book/pipeline/syntax/#agent"],
                ))
        return findings

    # -------------------------------------------------------- Azure Pipelines

    def _ado_pipelines(self, model: ArchitectureModel) -> list:
        return [c for c in model.components if c.service == "azure_pipeline"]

    def _check_ado_self_hosted_pr_trigger(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._ado_pipelines(model):
            pool_types = c.properties.get("agent_pool_types") or []
            if "self-hosted" in pool_types and c.properties.get("pr_trigger"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Pipeline '{c.name}' runs PR validation on a self-hosted agent pool",
                    description="A self-hosted agent pool that builds pull request triggers can execute arbitrary code from a fork or branch PR on your infrastructure — a classic RCE-via-PR path.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Restrict PR-triggered pipelines to Microsoft-hosted pools, or require PR builds to be approved before running on self-hosted agents.",
                    references=["https://learn.microsoft.com/en-us/azure/devops/pipelines/security/repos-source-code#pull-requests-from-forks"],
                ))
        return findings

    def _check_ado_persist_credentials(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._ado_pipelines(model):
            if c.properties.get("persist_credentials"):
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Pipeline '{c.name}' persists Git credentials on the agent",
                    description="persistCredentials: true leaves the pipeline's OAuth token in the local git config after checkout, where later steps or a compromised dependency can read and exfiltrate it.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Remove persistCredentials: true unless a later step explicitly needs to push to the repo, and prefer a scoped PAT for that case.",
                    references=["https://learn.microsoft.com/en-us/azure/devops/pipelines/repos/pipeline-options-for-git#checkout-options"],
                ))
        return findings

    def _check_ado_hardcoded_secrets(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._ado_pipelines(model):
            secrets = c.properties.get("hardcoded_secret_vars") or []
            if secrets:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Pipeline '{c.name}' has hardcoded secret-like variables: {', '.join(secrets)}",
                    description="Literal values for password/secret/token-like pipeline variables are stored in plaintext in the YAML and visible to anyone with repo read access.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Move these to a variable group backed by Azure Key Vault, or mark them as secret variables in the pipeline UI.",
                    references=["https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables#secret-variables"],
                ))
        return findings

    def _check_ado_self_hosted_recommend_scale_set(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in self._ado_pipelines(model):
            pool_types = c.properties.get("agent_pool_types") or []
            if "self-hosted" in pool_types:
                findings.append(Finding(
                    type=FindingType.SECURITY,
                    severity=Severity.LOW,
                    title=f"Pipeline '{c.name}' uses a static self-hosted agent pool",
                    description="Static self-hosted agents are long-lived and shared across runs — workspace files, cached credentials, and tool state can leak between jobs from different branches or repos.",
                    component_id=c.id,
                    component_name=c.name,
                    recommendation="Migrate to a Scale Set agent pool (Azure VM Scale Sets), which provisions a fresh, disposable agent per job.",
                    references=["https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/scale-set-agents"],
                ))
        return findings
