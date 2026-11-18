output "deploy_role_arn" {
  description = "Role the production release job assumes through OIDC"
  value       = aws_iam_role.deploy.arn
}

output "ecr_repositories" {
  value = { for k, r in aws_ecr_repository.service : k => r.repository_url }
}
