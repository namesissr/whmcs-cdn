# Local WHMCS test environment (PHP + ionCube + extensions WHMCS needs).
# WHMCS itself is NOT included: put your licensed WHMCS files in ./whmcs.
ARG PHP_VERSION=8.2
FROM php:${PHP_VERSION}-apache

# HTTPS mirrors: more reliable behind filtering/proxies
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      libpng-dev libjpeg62-turbo-dev libfreetype6-dev libzip-dev libicu-dev libgmp-dev libxml2-dev \
      unzip curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" pdo_mysql mysqli gd zip intl bcmath gmp soap

# ionCube Loader matching this PHP version and CPU (Intel or Apple Silicon)
RUN set -eux; \
    case "$(dpkg --print-architecture)" in amd64) arch=x86-64 ;; arm64) arch=aarch64 ;; *) echo "unsupported arch"; exit 1 ;; esac; \
    curl -fsSL "https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_${arch}.tar.gz" | tar xz -C /tmp; \
    v="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"; \
    cp "/tmp/ioncube/ioncube_loader_lin_${v}.so" "$(php -r 'echo ini_get("extension_dir");')/"; \
    echo "zend_extension=ioncube_loader_lin_${v}.so" > /usr/local/etc/php/conf.d/00-ioncube.ini; \
    rm -rf /tmp/ioncube; \
    php -v | grep -qi ioncube

RUN a2enmod rewrite \
 && printf 'memory_limit=256M\nupload_max_filesize=64M\npost_max_size=64M\nmax_execution_time=300\ndate.timezone=Asia/Tehran\n' \
      > /usr/local/etc/php/conf.d/whmcs.ini
