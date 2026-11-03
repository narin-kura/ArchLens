# Hand-written sample for a type no reference architecture uses yet.
# Attributes checked against the hashicorp/aws 6.x provider schema.
resource "aws_bedrockagentcore_agent_runtime" "agent" {
  agent_runtime_name = "support_agent"
  description        = "Customer-support agent"
  role_arn           = aws_iam_role.agent_runtime.arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${aws_ecr_repository.agent.repository_url}:v1"
    }
  }

  # Keep the runtime inside the VPC rather than on the public network.
  network_configuration {
    network_mode = "VPC"
    network_mode_config {
      subnets         = aws_subnet.private[*].id
      security_groups = [aws_security_group.agent.id]
    }
  }

  environment_variables = {
    LOG_LEVEL = "INFO"
  }
}
