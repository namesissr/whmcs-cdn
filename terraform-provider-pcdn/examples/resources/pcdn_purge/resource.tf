variable "release" {
  description = "Changing this value queues a new purge"
  type        = string
  default     = "v1"
}

# Exact URLs, purged again whenever var.release changes.
resource "pcdn_purge" "assets" {
  urls = [
    "https://example.com/assets/app.css",
    "https://example.com/assets/app.js",
  ]
  triggers = {
    release = var.release
  }
}

# Path prefixes (path or full URL prefix), e.g. after deploying the blog.
resource "pcdn_purge" "blog" {
  prefixes = ["/blog/", "https://example.com/img/"]
  triggers = {
    content_hash = sha1(join(",", ["post-1", "post-2"]))
  }
}

# The whole site cache.
resource "pcdn_purge" "all" {
  everything = true
  triggers = {
    release = var.release
  }
}
