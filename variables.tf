variable "zones" {
  type        = set(string)
  description = "需要下发规则的域名集合，例如 [\"example.com\",\"example.net\"]"
}
