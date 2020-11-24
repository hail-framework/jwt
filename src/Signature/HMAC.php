<?php

namespace Hail\Jwt\Signature;

use Hail\Jwt\SignatureInterface;
use Hail\Jwt\Util\Base64Url;
use Hail\Singleton\SingletonTrait;

final class HMAC implements SignatureInterface
{
    use SingletonTrait;

    public function available(): bool
    {
        return true;
    }

    public function sign(string $payload, $key, string $hash): string
    {
        return \hash_hmac($hash, $payload, $key, true);
    }

    public function verify(string $signature, string $payload, $key, string $hash): bool
    {
        return \hash_equals($signature, $this->sign($payload, $key, $hash));
    }

    public function getJWK($key): array
    {
        return [
            'kty' => 'oct',
            'k' => Base64Url::encode($key),
        ];
    }

    public function getPrivateKey(string $content, string $passphrase)
    {
        return $content;
    }

    public function getPublicKey(string $content)
    {
        return $content;
    }
}