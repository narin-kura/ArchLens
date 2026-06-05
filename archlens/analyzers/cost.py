"""Cost analyzer — flags expensive patterns and suggests cheaper alternatives."""

from __future__ import annotations

from .base import BaseAnalyzer
from ..models.architecture import ArchitectureModel, ComponentType
from ..models.findings import Finding, FindingType, Severity


# Rough monthly on-demand pricing (USD) for common instance sizes
_RDS_INSTANCE_COSTS: dict[str, float] = {
    "db.t3.micro": 13, "db.t3.small": 26, "db.t3.medium": 52,
    "db.r5.large": 175, "db.r5.xlarge": 350, "db.r5.2xlarge": 700,
    "db.r5.4xlarge": 1400, "db.r6g.large": 157, "db.r6g.xlarge": 314,
}

_EC2_INSTANCE_COSTS: dict[str, float] = {
    "t3.micro": 8, "t3.small": 17, "t3.medium": 34, "t3.large": 67,
    "m5.large": 87, "m5.xlarge": 175, "m5.2xlarge": 350,
    "r5.large": 121, "r5.xlarge": 243, "r5.2xlarge": 486,
}


class CostAnalyzer(BaseAnalyzer):
    def analyze(self, model: ArchitectureModel) -> list[Finding]:
        findings: list[Finding] = []
        for check in [
            self._check_oversized_rds,
            self._check_nat_gateway_vs_endpoints,
            self._check_no_auto_scaling,
            self._check_missing_reserved_instances_hint,
        ]:
            findings.extend(check(model))
        return findings

    def _check_oversized_rds(self, model: ArchitectureModel) -> list[Finding]:
        findings = []
        for c in model.components_by_type(ComponentType.DATABASE):
            instance_class = c.properties.get("instance_class", "")
            if not instance_class:
                continue
            current_cost = _RDS_INSTANCE_COSTS.get(instance_class)
            if current_cost and current_cost >= 350:
                # Suggest one size down
                alternatives = {k: v for k, v in _RDS_INSTANCE_COSTS.items() if v < current_cost * 0.6}
                if alternatives:
                    suggested = min(alternatives, key=alternatives.get)
                    savings = current_cost - alternatives[suggested]
                    findings.append(Finding(
                        type=FindingType.COST,
                        severity=Severity.MEDIUM,
                        title=f"Database '{c.name}' may be oversized ({instance_class})",
                        description=f"At ~${current_cost}/mo, consider right-sizing if CPU/memory utilization is low.",
                        component_id=c.id,
                        component_name=c.name,
                        recommendation=f"Switch to {suggested} (~${alternatives[suggested]}/mo) after reviewing CloudWatch metrics.",
                        estimated_savings=savings,
                    ))
        return findings

    def _check_nat_gateway_vs_endpoints(self, model: ArchitectureModel) -> list[Finding]:
        has_nat = any(
            "nat" in c.name.lower() or "nat" in c.service.lower()
            for c in model.components_by_type(ComponentType.NETWORK)
        )
        has_s3_or_dynamo = any(
            c.service in ("aws_s3_bucket", "aws_dynamodb_table")
            for c in model.components
        )
        if has_nat and has_s3_or_dynamo:
            return [Finding(
                type=FindingType.COST,
                severity=Severity.LOW,
                title="NAT Gateway detected with S3/DynamoDB — consider VPC endpoints",
                description="Traffic from private subnets to S3/DynamoDB via NAT Gateway incurs data processing charges (~$0.045/GB).",
                recommendation="Create VPC Gateway Endpoints for S3 and DynamoDB — free, and traffic stays within AWS network.",
                estimated_savings=40,
                references=["https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html"],
            )]
        return []

    def _check_no_auto_scaling(self, model: ArchitectureModel) -> list[Finding]:
        compute = model.components_by_type(ComponentType.COMPUTE)
        has_asg = any(
            "autoscaling" in c.service.lower() or "asg" in c.name.lower()
            for c in model.components
        )
        if compute and not has_asg:
            return [Finding(
                type=FindingType.COST,
                severity=Severity.LOW,
                title="No auto-scaling detected for compute resources",
                description="Fixed-size compute runs at full capacity 24/7 even during low-traffic periods.",
                recommendation="Add Auto Scaling Groups or use serverless (Lambda/Fargate) for variable workloads to reduce idle costs.",
                estimated_savings=0,
            )]
        return []

    def _check_missing_reserved_instances_hint(self, model: ArchitectureModel) -> list[Finding]:
        compute = model.components_by_type(ComponentType.COMPUTE)
        databases = model.components_by_type(ComponentType.DATABASE)
        if len(compute) + len(databases) >= 3:
            return [Finding(
                type=FindingType.COST,
                severity=Severity.INFO,
                title="Consider Reserved Instances or Savings Plans for predictable workloads",
                description=f"Detected {len(compute)} compute and {len(databases)} database resources running on-demand.",
                recommendation="1-year Reserved Instances save ~40%, 3-year ~60% vs on-demand. Savings Plans offer similar discounts with more flexibility.",
                estimated_savings=0,
            )]
        return []
