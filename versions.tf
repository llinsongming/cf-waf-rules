terraform {
  required_version = ">= 1.5.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 4.30.0"
    }
  }
  cloud {
    organization = "YOUR_TFC_ORG"
    workspaces { name = "YOUR_TFC_WORKSPACE" }
  }
}

provider "cloudflare" {}
