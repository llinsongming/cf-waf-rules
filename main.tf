resource "cloudflare_ruleset" "custom_waf" {
  for_each    = var.zones
  zone_id     = each.value
  name        = "Custom WAF Rules"
  description = "Skip verified bots & Google UA; block ad click fraud"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      action      = "skip"
      description = "Allow Verified Bots (skip WAF)"
      expression  = "cf.client.bot"
      enabled     = true
      action_parameters = { products = ["waf"] }
    },
    {
      action      = "skip"
      description = "Allow Google UA (skip WAF)"
      expression  = "(http.user_agent contains \"AdsBot-Google\" or http.user_agent contains \"Google-InspectionTool\" or http.user_agent contains \"Googlebot\" or http.user_agent contains \"Mediapartners-Google\")"
      enabled     = true
      action_parameters = { products = ["waf"] }
    },
    {
      action      = "block"
      description = "Ad Click Guard (block)"
      enabled     = true
      expression  = <<-EOT
not cf.client.bot
and (
  lower(http.request.uri.query) contains "gclid="
  or lower(http.request.uri.query) contains "gbraid="
  or lower(http.request.uri.query) contains "wbraid="
  or lower(http.request.uri.query) contains "gad_source="
)
and not (
  lower(http.user_agent) contains "iphone"
  or ( lower(http.user_agent) contains "android" and lower(http.user_agent) contains "mobile" )
  or lower(http.user_agent) contains "windows phone"
  or lower(http.user_agent) contains "ipod"
)
EOT
    },
  ]
}
