<?php

namespace Hail\Jwt\Signature;

use Hail\Jwt\SignatureInterface;
use Hail\Jwt\Util\Base64Url;
use Hail\Singleton\SingletonTrait;

class RSA implements SignatureInterface
{
    use SingletonTrait;

    protected const KEY_TYPE = \OPENSSL_KEYTYPE_RSA;

    protected const JWT_KTY = 'rsa';
    protected const JWT_MAP = [
        'n' => 'n',
        'd' => 'd',
        'e' => 'e',
        'p' => 'p',
        'q' => 'q',
        'dmp1' => 'dp',
        'dmq1' => 'dq',
        'iqmp' => 'qi',
    ];

    public function available(): bool
    {
        return true;
    }

    public function sign(string $payload, $key, string $hash): string
    {
        if (!\is_resource($key)) {
            throw new \InvalidArgumentException('Key is not a openssl key resource');
        }

        $signature = '';
        if (!\openssl_sign($payload, $signature, $key, $hash)) {
            throw new \DomainException(
                'There was an error while creating the signature: ' . \openssl_error_string()
            );
        }

        return $signature;
    }

    public function verify(string $signature, string $payload, $key, string $hash): bool
    {
        if (!\is_resource($key)) {
            throw new \InvalidArgumentException('Key is not a openssl key resource');
        }

        switch (\openssl_verify($payload, $signature, $key, $hash)) {
            case 1:
                return true;

            case 0:
                return false;

            default:
                // returns 1 on success, 0 on failure, -1 on error.
                throw new \DomainException('OpenSSL error: ' . \openssl_error_string());
        }
    }

    public function getPrivateKey(string $content, string $passphrase)
    {
        $key = \openssl_pkey_get_private($content, $passphrase);
        $this->validateKey($key);

        return $key;
    }

    public function getPublicKey(string $content)
    {
        $key = \openssl_pkey_get_private($content);

        if ($key === false) {
            $key = \openssl_pkey_get_public($content);
            $this->validateKey($key);
        } else {
            $key = \openssl_pkey_get_public(
                $this->validateKey($key)['key']
            );
        }

        return $key;
    }

    protected function validateKey($key)
    {
        if (!\is_resource($key)) {
            throw new \InvalidArgumentException(
                'It was not possible to parse your key, reason: ' . \openssl_error_string()
            );
        }

        $details = \openssl_pkey_get_details($key);

        if (!isset($details['key']) || $details['type'] !== static::KEY_TYPE) {
            throw new \InvalidArgumentException('This key is not compatible with RSA');
        }

        return $details;
    }

    public function getJWK($key): array
    {
        $details = $this->validateKey($key);

        $jwk = [
            'kty' => \strtoupper(static::JWT_KTY),
        ];

        foreach ($details[static::JWT_KTY] as $k => $v) {
            if (isset(static::JWT_MAP[$k])) {
                $jwk[static::JWT_MAP[$k]] = Base64Url::encode($v);
            }
        }

        return $jwk;
    }
}