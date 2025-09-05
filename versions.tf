terraform {
  required_version = ">= 1.5.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 4.50.0"
    }
  }
  cloud {
    organization = "ming807598914"
    workspaces { name = "cloudflare" }
  }
}

provider "cloudflare" {}
