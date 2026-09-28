<?php

namespace PasargadCdn;

class ApiException extends \Exception
{
}

/**
 * Thin client for the CDN controller API.
 */
class ApiClient
{
    private string $baseUrl;
    private string $apiKey;
    private int $timeout;

    public function __construct(string $baseUrl, string $apiKey, int $timeout = 20)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->apiKey = $apiKey;
        $this->timeout = $timeout;
    }

    public static function fromParams(array $params): self
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
        return new self($host, $key);
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
        $ch = curl_init($this->baseUrl . $path);
        $headers = [
            'Authorization: Bearer ' . $this->apiKey,
            'Accept: application/json',
        ];
        $payload = null;
        if ($body !== null && $method !== 'GET') {
            $payload = json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $headers[] = 'Content-Type: application/json';
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        }
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if (function_exists('logModuleCall')) {
            logModuleCall('pasargadcdn', $method . ' ' . $path, $payload, $raw, null, [$this->apiKey]);
        }
        if ($raw === false) {
            throw new ApiException('اتصال به سرور CDN برقرار نشد: ' . $err);
        }
        $data = json_decode((string) $raw, true);
        if ($code >= 400) {
            throw new ApiException(self::errorMessage($data, $code), $code);
        }
        return is_array($data) ? $data : [];
    }

    private static function errorMessage($data, int $code): string
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
            return implode('، ', $msgs);
        }
        return 'خطای سرور CDN (HTTP ' . $code . ')';
    }
}
