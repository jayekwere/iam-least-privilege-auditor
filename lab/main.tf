terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.71.0"
    }
  }
}
variable "sandbox_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.sandbox_account_id))
    error_message = "Supply the explicitly authorized sandbox account ID."
  }
}
variable "enable_lab" {
  type    = bool
  default = false
}
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.sandbox_account_id]
}
resource "aws_iam_user" "review" {
  count                = var.enable_lab ? 1 : 0
  name                 = "iam-auditor-lab-review"
  permissions_boundary = aws_iam_policy.boundary[0].arn
}
resource "aws_iam_policy" "boundary" {
  count = var.enable_lab ? 1 : 0
  name  = "iam-auditor-lab-boundary"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::iam-auditor-fictional/*"
  }] })
}
resource "aws_iam_user_policy" "broad" {
  count = var.enable_lab ? 1 : 0
  user  = aws_iam_user.review[0].name
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["*"], Resource = "*"
  }] })
}
resource "aws_iam_role" "trust" {
  for_each = var.enable_lab ? toset(["guarded", "unguarded"]) : toset([])
  name     = "iam-auditor-lab-${each.key}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Principal = { AWS = "arn:aws:iam::${var.sandbox_account_id}:root" },
    Action    = "sts:AssumeRole",
    Condition = each.key == "guarded" ? { StringEquals = { "sts:ExternalId" = "lab-example-delegation" } } : {}
  }] })
}
resource "aws_iam_role_policy" "passrole" {
  for_each = aws_iam_role.trust
  role     = each.value.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["iam:PassRole"], Resource = "*"
  }] })
}
