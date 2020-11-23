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

    public function __construct(string $algorithm, ?string $key, string $passphrase = '')
    {
        $this->algorithm = self::supported($algorithm);
        $this->signature = $this->getSignature($algorithm);

        if ($key !== null) {
            $this->setKey($key, $passphrase);
        }
    }

    public function setKey(string $key, string $passphrase = ''): void
    {
        $this->key = $key;
        $this->passphrase = $passphrase;
    }

    private function getKey($type)
    {
        if (empty($this->key)) {
            throw new \LogicException('Key not set');
        }

        if ($type === 'sign') {
            return $this->signature->getPrivateKey($this->key, $this->passphrase);
        }

        if ($type === 'verify') {
            return $this->signature->getPublicKey($this->key);
        }

        throw new \LogicException('unknown method');
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
        return $this->signature->sign($payload, $this->getKey(__FUNCTION__), $this->hash);
    }

    public function verify(string $signature, string $payload): bool
    {
        return $this->signature->verify($signature, $payload, $this->getKey(__FUNCTION__), $this->hash);
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