data "cloudflare_zones" "all" {
  filter {
    status = "active"
  }
}

locals {
  account_zones_map = { for zone in data.cloudflare_zones.all.zones : zone.name => zone }

  target_zones = {
    for zone_name in var.zones : zone_name => local.account_zones_map[zone_name]
    if lookup(local.account_zones_map, zone_name, null) != null
  }
}

resource "cloudflare_ruleset" "custom_waf" {
  for_each    = local.target_zones
  zone_id     = each.value.id
  name        = "Custom WAF Rules"
  description = "Skip verified bots & Google UA; block ad click fraud"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules {
    action      = "skip"
    description = "Allow Verified Bots (skip WAF)"
    expression  = "cf.client.bot"
    enabled     = true
    action_parameters { products = ["waf"] }
    logging { enabled = true }
  }

  rules {
    action      = "skip"
    description = "Allow Google UA (skip WAF)"
    expression  = "(http.user_agent contains \"AdsBot-Google\" or http.user_agent contains \"Google-InspectionTool\" or http.user_agent contains \"Googlebot\" or http.user_agent contains \"Mediapartners-Google\")"
    enabled     = true
    action_parameters { products = ["waf"] }
    logging { enabled = true }
  }

  rules {
    action      = "block"
    description = "Ad Click Guard (block)"
    enabled     = true
    expression  = <<-EOT
not cf.client.bot
and ip.geoip.asnum ne 15169
and (
  lower(http.request.uri.query) contains "gclid="
  or lower(http.request.uri.query) contains "gbraid="
  or lower(http.request.uri.query) contains "wbraid="
  or lower(http.request.uri.query) contains "gad_source="
)
and (
  ip.geoip.asnum in {
    16509 14618 8075 31898 16276 24940 14061 20473 63949 12876
    9009 51167 60781 16265 28753 30633 3223 40676 20454 54825
    32181 40009 38136 199524 202425 45102 37963 45177 132203 45090
    21859 31034 23470 35908 15003 8100 62904 14742 60068 49544
    29802 18450 46475 26347 396982
  }
  or not (
    lower(http.user_agent) contains "iphone"
    or ( lower(http.user_agent) contains "android" and lower(http.user_agent) contains "mobile" )
    or lower(http.user_agent) contains "windows phone"
    or lower(http.user_agent) contains "ipod"
  )
  or not (
    lower(http.request.headers["accept-language"][0]) contains "de"
  )
)
EOT
    logging { enabled = true }
  }
}
