{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "apigateway:GET",
        "apigateway:GET/*",
        "apigatewayv2:GetApis",
        "wafv2:ListWebACLs",
        "wafv2:ListResourcesForWebACL",
        "config:PutEvaluations",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
