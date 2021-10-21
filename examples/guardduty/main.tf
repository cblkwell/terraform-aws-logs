module "aws_logs" {
  source = "../../"

  s3_bucket_name        = var.test_name
  allow_guardduty       = true
  default_allow         = false
  guardduty_logs_prefix = var.guardduty_logs_prefix

  force_destroy = var.force_destroy
}

module "guardduty" {
  source  = "dod-iac/guardduty/aws"
  version = "~> 1"

  s3_bucket_name = module.aws_logs.aws_logs_bucket
}

/*
The MIT License (MIT)

Copyright (c) 2021 U.S. Department of Defense, Defense Digital Service

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "key_policy" {
  policy_id = "key-consolepolicy"
  statement {
    sid = "Enable IAM User Permissions"
    actions = [
      "kms:*"
    ]
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = [
        format(
          "arn:%s:iam::%s:root",
          data.aws_partition.current.partition,
          data.aws_caller_identity.current.account_id
        )
      ]
    }
    resources = ["*"]
  }
  statement {
    sid = "Allow GuardDuty to use the key"
    actions = [
      "kms:GenerateDataKey"
    ]
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com"
      ]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key" "guardduty" {
  description             = "Key used to encrypt GuardDuty findings."
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.key_policy.json
  enable_key_rotation     = true
  tags                    = var.kms_key_tags
}

resource "aws_kms_alias" "guardduty" {
  name          = var.kms_alias_name
  target_key_id = aws_kms_key.guardduty.key_id
}

resource "aws_guardduty_detector" "main" {
  enable                       = var.enable
  finding_publishing_frequency = var.finding_publishing_frequency
  depends_on = [
    aws_kms_key.guardduty,
    aws_kms_alias.guardduty
  ]
}

data "aws_s3_bucket" "main" {
  bucket = module.aws_logs.aws_logs_bucket
}

# GuardDuty expects a folder to exist, otherwise it throws an error.
resource "aws_s3_bucket_object" "guardduty" {
  bucket = data.aws_s3_bucket.main.id
  acl    = "private"
  key = var.s3_bucket_prefix == "/" ? "/" : format("%s/", (
    substr(var.s3_bucket_prefix, 0, 1) == "/" ?
    substr(var.s3_bucket_prefix, 1, length(var.s3_bucket_prefix)) :
    var.s3_bucket_prefix
  ))
  source = "/dev/null"
}

resource "aws_guardduty_publishing_destination" "main" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = format("%s%s", data.aws_s3_bucket.main.arn, (length(var.s3_bucket_prefix) > 0 ? var.s3_bucket_prefix : "/"))
  kms_key_arn     = aws_kms_key.guardduty.arn
  depends_on = [
    aws_s3_bucket_object.guardduty
  ]
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name          = "guardduty-finding-events"
  description   = "AWS GuardDuty event findings"
  event_pattern = <<EOF
  {
    "detail-type": [
      "GuardDuty Finding"
    ],
    "source": [
      "aws.guardduty"
    ]
  }
  EOF
}