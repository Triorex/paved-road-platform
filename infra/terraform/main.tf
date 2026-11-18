data "aws_caller_identity" "current" {}

# --- GitHub Actions OIDC: no long-lived AWS keys in any repository ---------------------------
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"] # retained for older providers; AWS validates GitHub via its CA library
  tags            = var.tags
}

# The org's OIDC subject is customised to "repo:<org>/<repo>:environment:<env>:job_workflow_ref:<ref>"
# (governance/oidc-subject.json), so this condition admits ONLY production deploys run by the
# central release workflow, from any repo in the org, and nothing else.
data "aws_iam_policy_document" "deploy_trust" {
  statement {
    sid     = "PavedRoadProductionReleaseOnly"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/*:environment:production:job_workflow_ref:${var.github_org}/${var.platform_repo}/.github/workflows/release.yml@*"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = "paved-road-deploy"
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust.json
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "PushToPavedRoadRepositories"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"]
    resources = [for r in aws_ecr_repository.service : r.arn]
  }
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] #trivy:ignore:AVD-AWS-0057 ecr:GetAuthorizationToken does not support resource-level permissions
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "paved-road-deploy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}

# --- Encryption ------------------------------------------------------------------------------
resource "aws_kms_key" "ecr" {
  description             = "Paved road: ECR image encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "ecr" {
  name          = "alias/paved-road-ecr"
  target_key_id = aws_kms_key.ecr.key_id
}

# --- Registries: immutable, scanned, encrypted -----------------------------------------------
resource "aws_ecr_repository" "service" {
  for_each             = var.services
  name                 = "${lower(var.github_org)}/${each.value}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "service" {
  for_each   = aws_ecr_repository.service
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 14 days"
      selection    = { tagStatus = "untagged", countType = "sinceImagePushed", countUnit = "days", countNumber = 14 }
      action       = { type = "expire" }
    }]
  })
}
