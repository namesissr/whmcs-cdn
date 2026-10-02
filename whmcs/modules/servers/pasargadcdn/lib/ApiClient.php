<?php

namespace PasargadCdn;

require_once __DIR__ . '/I18n.php';

if (!class_exists(__NAMESPACE__ . '\\ApiException', false)) {
    class ApiException extends \Exception
    {
    }
}

if (class_exists(__NAMESPACE__ . '\\ApiClient', false)) {
    return;
}

/**
 * Thin client for the CDN controller API.
 */
class ApiClient
{
    private string $baseUrl;
    private string $apiKey;
    private int $timeout;
    /** SPEC §20.3: X-PCDN-Actor of a shared member's write (`share:<client id>:<role>`), '' = none */
    private string $actor = '';

    public function __construct(string $baseUrl, string $apiKey, int $timeout = 20)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->apiKey = $apiKey;
        $this->timeout = $timeout;
    }

    /** @param int $timeout total seconds per request (connect timeout is capped at 10 s) */
    public static function fromParams(array $params, int $timeout = 20): self
    {
        $host = trim($params['serverhostname'] ?? '') ?: trim($params['serverip'] ?? '');
        if ($host === '') {
            throw new ApiException('Server hostname is not configured');
        }
        if (!preg_match('#^https?://#i', $host)) {
            $scheme = !empty($params['serversecure']) ? 'https' : 'http';
            $port = (int) ($params['serverport'] ?? 0);
            $host = $scheme . '://' . $host . ($port && !in_array($port, [80, 443], true) ? ':' . $port : '');
        }
        $key = trim($params['serveraccesshash'] ?? '') ?: (string) ($params['serverpassword'] ?? '');
        if ($key === '') {
            throw new ApiException('API key is not configured (put it in the server "Access Hash" field)');
        }
        return new self($host, $key, $timeout);
    }

    /**
     * Client for a tblservers row (object or array with type/hostname/ipaddress/
     * secure/port/accesshash/password). The password column is WHMCS-encrypted.
     */
    public static function fromServerRow($server, int $timeout = 20): self
    {
        $s = (array) $server;
        $hash = trim((string) ($s['accesshash'] ?? ''));
        $password = '';
        if ($hash === '' && (string) ($s['password'] ?? '') !== '') {
            $password = function_exists('decrypt') ? (string) decrypt($s['password']) : (string) $s['password'];
        }
        return self::fromParams([
            'serverhostname' => $s['hostname'] ?? '',
            'serverip' => $s['ipaddress'] ?? '',
            'serversecure' => $s['secure'] ?? '',
            'serverport' => $s['port'] ?? '',
            'serveraccesshash' => $hash,
            'serverpassword' => $password,
        ], $timeout);
    }

    /**
     * SPEC §20.3: forward who acts on behalf of the owner (the controller records it as `on_behalf_of`). Only
     * `[a-z0-9:_-]{1,64}` is ever sent; anything else clears it.
     */
    public function setActor(string $actor): self
    {
        $this->actor = preg_match('/^[a-z0-9:_-]{1,64}$/D', $actor) ? $actor : '';
        return $this;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    /**
     * Parallel GETs (curl_multi) bounded by this client's timeout in total.
     * Never throws: returns [path => ['code' => int, 'data' => mixed, 'error' => ?string]].
     */
    public function getMany(array $paths): array
    {
        $reqs = [];
        foreach (array_values(array_unique($paths)) as $path) {
            $reqs[$path] = ['GET', $path, null];
        }
        return $this->requestMany($reqs);
    }

    /**
     * Parallel requests (curl_multi) bounded by this client's timeout in total.
     * $reqs: [key => [method, path, ?array body]]. Never throws: returns
     * [key => ['code' => int, 'data' => mixed, 'error' => ?string]] (code 0 = no answer).
     */
    public function requestMany(array $reqs): array
    {
        $out = [];
        if (!$reqs) {
            return $out;
        }
        $mh = curl_multi_init();
        $handles = [];
        foreach ($reqs as $key => [$method, $path, $body]) {
            $payload = ($body !== null && $method !== 'GET')
                ? json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null;
            $ch = curl_init($this->baseUrl . $path);
            curl_setopt_array($ch, $this->curlOptions($method, $payload));
            curl_multi_add_handle($mh, $ch);
            $handles[$key] = [$ch, $method . ' ' . $path, $payload];
        }
        $deadline = microtime(true) + $this->timeout + 1;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) {
                curl_multi_select($mh, 0.2);
            }
        } while ($running && $status === CURLM_OK && microtime(true) < $deadline);
        foreach ($handles as $key => [$ch, $label, $payload]) {
            $raw = curl_multi_getcontent($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_error($ch);
            if (function_exists('logModuleCall')) {
                logModuleCall('pasargadcdn', $label, self::redact($payload), self::redact($raw), null, [$this->apiKey]);
            }
            if ($code === 0 || $raw === null || $raw === false) {
                $out[$key] = ['code' => 0, 'data' => null, 'error' => $err !== '' ? I18n::tr('اتصال به سرور CDN برقرار نشد: %s', $err) : I18n::tr('اتصال به سرور CDN برقرار نشد')];
            } else {
                $data = json_decode((string) $raw, true);
                $out[$key] = ['code' => $code, 'data' => $data,
                    'error' => $code >= 400 ? self::errorMessage($data, $code) : null];
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);
        return $out;
    }

    private function curlOptions(string $method, ?string $payload): array
    {
        $headers = [
            'Authorization: Bearer ' . $this->apiKey,
            'Accept: application/json',
        ];
        if ($this->actor !== '' && $method !== 'GET') {
            $headers[] = 'X-PCDN-Actor: ' . $this->actor;
        }
        $opts = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => max(1, min(10, $this->timeout)),
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_NOSIGNAL => true,
        ];
        if ($payload !== null) {
            $headers[] = 'Content-Type: application/json';
            $opts[CURLOPT_POSTFIELDS] = $payload;
        }
        $opts[CURLOPT_HTTPHEADER] = $headers;
        return $opts;
    }

    public function get(string $path): array
    {
        return $this->request('GET', $path);
    }

    public function post(string $path, array $body = []): array
    {
        return $this->request('POST', $path, $body);
    }

    public function put(string $path, array $body): array
    {
        return $this->request('PUT', $path, $body);
    }

    public function patch(string $path, array $body): array
    {
        return $this->request('PATCH', $path, $body);
    }

    public function delete(string $path): array
    {
        return $this->request('DELETE', $path);
    }

    public static function site(string $domain): string
    {
        return '/api/v1/sites/' . rawurlencode(strtolower(trim($domain)));
    }

    public function request(string $method, string $path, ?array $body = null): array
    {
        $payload = ($body !== null && $method !== 'GET')
            ? json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
            : null;
        [$code, $data] = $this->raw($method, $path, $payload);
        if ($code >= 400) {
            throw new ApiException(self::errorMessage($data, $code), $code);
        }
        return is_array($data) ? $data : [];
    }

    /**
     * Low-level call used by request() and by the client-area JSON proxy,
     * which needs the controller's status code and body as they are.
     * Returns [http status, decoded JSON (null when not JSON)].
     */
    public function raw(string $method, string $path, ?string $payload = null): array
    {
        $ch = curl_init($this->baseUrl . $path);
        curl_setopt_array($ch, $this->curlOptions($method, $payload));
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', $method . ' ' . $path, self::redact($payload), self::redact($raw), null, [$this->apiKey]);
        }
        if ($raw === false) {
            throw new ApiException(I18n::tr('اتصال به سرور CDN برقرار نشد: %s', $err));
        }
        return [$code, json_decode((string) $raw, true)];
    }

    /**
     * A public, non-JSON controller file (e.g. GET /origin-pull-ca.pem, SPEC §14.2) as text.
     * Sent without the admin key (the file is public) and refused past $max bytes.
     * Returns [http status, body] — body is null when it was larger than $max.
     */
    public function rawText(string $method, string $path, int $max = 262144): array
    {
        $ch = curl_init($this->baseUrl . $path);
        $opts = $this->curlOptions($method, null);
        $opts[CURLOPT_HTTPHEADER] = ['Accept: application/x-pem-file, text/plain;q=0.9, */*;q=0.1'];
        $opts[CURLOPT_MAXFILESIZE] = $max;
        curl_setopt_array($ch, $opts);
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', $method . ' ' . $path, null, self::redact(is_string($raw) ? substr($raw, 0, 4096) : $raw), null, [$this->apiKey]);
        }
        if ($raw === false) {
            throw new ApiException(I18n::tr('اتصال به سرور CDN برقرار نشد: %s', $err));
        }
        return [$code, strlen((string) $raw) > $max ? null : (string) $raw];
    }

    /**
     * SPEC §18.3: a binary/text download from the controller (statement PDF/CSV, audit CSV), sent WITH the
     * admin key. The transfer is aborted past $max bytes. Returns [http status, body|null (null = larger than
     * $max), content type]. The module log gets the size and type only, never the document.
     */
    public function download(string $path, int $max, string $accept = 'application/pdf, text/csv, application/json;q=0.5'): array
    {
        $ch = curl_init($this->baseUrl . $path);
        $opts = $this->curlOptions('GET', null);
        $opts[CURLOPT_HTTPHEADER] = ['Authorization: Bearer ' . $this->apiKey, 'Accept: ' . $accept];
        $buf = '';
        $over = false;
        $opts[CURLOPT_RETURNTRANSFER] = false;
        $opts[CURLOPT_WRITEFUNCTION] = function ($h, $chunk) use (&$buf, &$over, $max) {
            if (strlen($buf) + strlen($chunk) > $max) {
                $over = true;
                return 0;   // aborts the transfer
            }
            $buf .= $chunk;
            return strlen($chunk);
        };
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $type = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $err = curl_error($ch);
        curl_close($ch);
        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', 'GET ' . $path, null, $over ? 'download larger than ' . $max . ' bytes (aborted)'
                : 'HTTP ' . $code . ', ' . $type . ', ' . strlen($buf) . ' bytes', null, [$this->apiKey]);
        }
        if ($over) {
            return [$code ?: 200, null, $type];
        }
        if ($ok === false) {
            throw new ApiException(I18n::tr('اتصال به سرور CDN برقرار نشد: %s', $err));
        }
        return [$code, $buf, $type];
    }

    /**
     * Secrets never reach the WHMCS module log: edge tokens (shown to the admin
     * once), private keys of custom certificates, and (SPEC §14.3) the log-export
     * S3 keys in `logs` bodies plus webhook signing secrets — `new_secrets` of a
     * webhooks PUT, the `secret` of a rotation and any `whsec_…` value; (SPEC §16.8) the
     * `secret_key` (and `access_key`) of a storage bucket create / rotate-key answer; (SPEC §16.9) the
     * `code` of edge functions (customer source, up to 8 MB per site, may embed the customer's own
     * tokens) — the log keeps ids, routes, sizes and hashes only, like the controller's audit.
     */
    public static function redact($text)
    {
        if (!is_string($text) || $text === '') {
            return $text;
        }
        // SPEC §18.1/§18.2: the per-site waiting-room / access secrets never leave the controller, masked anyway
        $text = (string) preg_replace('/"(token|key|secret|secret_key|access_key|transform_secret|tsig_secret|access_secret|wr_secret)"\s*:\s*"(?:[^"\\\\]|\\\\.)*"/', '"$1":"***"', $text);
        $text = (string) preg_replace('/"new_secrets"\s*:\s*\{[^{}]*\}/', '"new_secrets":"***"', $text);
        // possessive: linear on megabytes of escaped JavaScript; a PCRE failure logs nothing rather than the code
        $text = preg_replace('/"code"\s*:\s*"(?:[^"\\\\]++|\\\\.)*+"/', '"code":"***"', $text);
        if (!is_string($text)) {
            return '';
        }
        $text = (string) preg_replace('/whsec_[0-9A-Za-z]+/', 'whsec_***', $text);
        // Wave 8 (SPEC §16.6): image transform secrets (imgsec_ + hex) wherever they appear
        $text = (string) preg_replace('/imgsec_[0-9A-Za-z]+/', 'imgsec_***', $text);
        // One-time edge tokens can also appear embedded in install/bootstrap one-liner strings
        // (e.g. the batch response's `install`), so mask the token value wherever it occurs.
        $text = (string) preg_replace('/edge_[0-9a-f]{16,}/', 'edge_***', $text);
        return (string) preg_replace('/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/s', '***PRIVATE KEY***', $text);
    }

    public static function errorMessage($data, int $code): string
    {
        $detail = is_array($data) ? ($data['detail'] ?? null) : null;
        if (is_string($detail)) {
            return $detail;
        }
        if (is_array($detail)) {
            $msgs = [];
            foreach ($detail as $d) {
                $field = is_array($d['loc'] ?? null) ? end($d['loc']) : '';
                $msgs[] = trim($field . ': ' . ($d['msg'] ?? ''), ': ');
            }
            return implode(I18n::tr('، '), $msgs);
        }
        return I18n::tr('خطای سرور CDN (HTTP %s)', $code);
    }
}
