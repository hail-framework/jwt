<?php

namespace Hail\Jwt;

use Hail\Jwt\Signature\{EdDSA, HMAC, RSA, ECDSA, PSS};

final class Signer
{
    public const
        EdDSA = 'EdDSA',
        HS256 = 'HS256',
        HS384 = 'HS384',
        HS512 = 'HS512',
        RS256 = 'RS256',
        RS384 = 'RS384',
        RS512 = 'RS512',
        ES256 = 'ES256',
        ES384 = 'ES384',
        ES512 = 'ES512',
        ES256K = 'ES256K',
        PS256 = 'PS256',
        PS384 = 'PS384',
        PS512 = 'PS512';

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var string|null
     */
    private $hash;

    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $passphrase = '';

    /**
     * @var SignatureInterface
     */
    private $signature;

    /**
     * @var array
     */
    private $cache = [];

    public function __construct(string $algorithm, ?string $key, string $passphrase = '')
    {
        $this->algorithm = self::supported($algorithm);
        $this->signature = $this->getSignature($algorithm);

        if ($key !== null) {
            $this->setKey($key, $passphrase);
        }
    }

    public function __destruct()
    {
        foreach ($this->cache as $key) {
            if (\is_resource($key) || $key instanceof \OpenSSLAsymmetricKey) {
                \openssl_free_key($key);
            }
        }
    }

    public function setKey(string $key, string $passphrase = ''): void
    {
        $this->key = $key;
        $this->passphrase = $passphrase;
        $this->cache = [];
    }

    private function getPrivateKey()
    {
        if (empty($this->key)) {
            throw new \LogicException('Key not set');
        }

        return $this->cache['private'] ?? $this->cache['private'] = $this->signature->getPrivateKey($this->key, $this->passphrase);
    }

    private function getPublicKey()
    {
        if (empty($this->key)) {
            throw new \LogicException('Key not set');
        }

        return $this->cache['public'] ?? $this->cache['public'] = $this->signature->getPublicKey($this->key);
    }

    public static function supported($algorithm)
    {
        if (!\defined(self::class . '::' . $algorithm)) {
            throw new \UnexpectedValueException('Signature algorithm not supported');
        }

        return $algorithm;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function sign(string $payload): string
    {
        $key = $this->cache['private'] ?? $this->getPrivateKey();

        return $this->signature->sign($payload, $key, $this->hash);
    }

    public function verify(string $signature, string $payload): bool
    {
        $key = $this->cache['public'] ?? $this->getPublicKey();

        return $this->signature->verify($signature, $payload, $key, $this->hash);
    }

    private function getSignature($algorithm)
    {
        $this->hash = 'sha' . \substr($algorithm, 2, 3);

        switch(\substr($algorithm, 0, 2)) {
            case 'HS':
                return HMAC::getInstance();

            case 'RS':
                return RSA::getInstance();

            case 'ES':
                return ECDSA::getInstance();

            case 'PS':
                return PSS::getInstance();

            default:
                $this->hash = null;

                if ($algorithm === self::EdDSA) {
                    $instance = EdDSA::getInstance();
                    if (!$instance->available()) {
                        throw new \UnexpectedValueException('You must install "ext-sodium" to support EdDSA.');
                    }

                    return $instance;
                }
        }

        throw new \UnexpectedValueException('Signature algorithm not supported');
    }
}