<?php

namespace Hail\Jwt\Signature;

use Hail\Jwt\SignatureInterface;
use Hail\Jwt\Util\Base64Url;
use Hail\Singleton\SingletonTrait;

\defined('SODIUM_EXTENSION') || \define('SODIUM_EXTENSION', \extension_loaded('sodium'));

/**
 * Class EdDSA
 * only for crv Ed25519
 *
 * @package Hail\Jwt\Signature
 */
class EdDSA implements SignatureInterface
{
    use SingletonTrait;

    public function available(): bool
    {
        return SODIUM_EXTENSION;
    }

    public function sign(string $payload, $key, string $hash): string
    {
        return \sodium_crypto_sign_detached($payload, $key);
    }

    public function verify(string $signature, string $payload, $key, string $hash): bool
    {
        return \sodium_crypto_sign_verify_detached($signature, $payload, $key);
    }

    public function getPrivateKey(string $content, string $passphrase)
    {
        $key = \hex2bin($content);
        $length = \mb_strlen($key, '8bit');

        if ($length === 32) {
            $keyPair = \sodium_crypto_sign_seed_keypair($content);

            return \sodium_crypto_sign_secretkey($keyPair);
        }

        if ($length === 64) {
            return $content;
        }

        throw new \InvalidArgumentException('Invalid Ed25519 Key');
    }

    public function getPublicKey(string $content)
    {
        $key = \hex2bin($content);
        $length = \mb_strlen($key, '8bit');

        if ($length === 32) {
            return $key;
        }

        if ($length === 64) {
            $secretKey = \mb_substr($key, 0, 32, '8bit');
            $publicKey = \mb_substr($key, 32, null, '8bit');

            $keyPair = \sodium_crypto_sign_seed_keypair($secretKey);
            if (\sodium_crypto_sign_publickey($keyPair) === $publicKey) {
                return $publicKey;
            }
        }

        throw new \InvalidArgumentException('Invalid Ed25519 Key');
    }

    public function getJWK($key): array
    {
        $key = \hex2bin($key);
        $length = \mb_strlen($key, '8bit');

        if ($length === 64) {
            $d = \mb_substr($key, 0, 32, '8bit');
            $x = $this->getPublicKey($key);
        } elseif ($length === 32) {
            $d = $key;
            $secretKey = $this->getPrivateKey($key, '');
            $x = \mb_substr($secretKey, 32, null, '8bit');
        } else {
            throw new \InvalidArgumentException('Invalid Ed25519 Key');
        }

        return [
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd' => Base64Url::encode($d),
            'x' => Base64Url::encode($x),
        ];
    }
}