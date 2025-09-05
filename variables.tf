variable "zones" {
  type        = map(string)
  description = "域名到 zone_id 的映射，例如 { \"example.com\" = \"<ZONE_ID>\" }"
}
