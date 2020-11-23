<?php

namespace Hail\Jwt;

use Hail\Jwt\Util\Base64Url;

class JWTBuilder
{
    /**
     * The token header
     *
     *  The algorithm `none` is not safe, only use for init.
     *  If not set `alg` to any others, the builder will throw a exception when JWT building.
     *
     * @var array
     */
    protected $headers = [
        'typ' => 'JWT',
        'alg' => 'none',
    ];

    /**
     * The token claim set
     *
     * @var array
     */
    protected $claims = [];

    /**
     * @var Signer
     */
    protected $signer;

    protected $key;
    protected $passphrase = '';

    public function __construct(array $config = [])
    {
        foreach ($config as $k => $v) {
            switch ($k) {
                case 'alg':
                    $this->setAlgorithm($v);
                    break;

                case 'key':
                    $v = (array) $v;
                    $this->setKey(...$v);
                    break;

                case RegisteredClaims::AUDIENCE:
                    $this->claims[RegisteredClaims::AUDIENCE] = (array) $v;
                    break;

                case RegisteredClaims::EXPIRATION_TIME:
                    $this->setExpiresAt($v);
                    break;

                case RegisteredClaims::ID:
                    $this->setIdentifier($v);
                    break;

                case RegisteredClaims::ISSUED_AT:
                    $this->setIssuedAt($v);
                    break;

                case RegisteredClaims::ISSUER:
                    $this->setIssuer($v);
                    break;

                case RegisteredClaims::NOT_BEFORE:
                    $this->setNotBefore($v);
                    break;

                case RegisteredClaims::SUBJECT:
                    $this->setSubject($v);
                    break;
            }
        }
    }

    public function setAlgorithm($alg): JWTBuilder
    {
        $this->headers['alg'] = Signer::supported($alg);
        $this->signer = null;

        return $this;
    }

    public function setKey(string $key, string $passphrase = ''): JWTBuilder
    {
        $this->key = $key;
        $this->passphrase = $passphrase;
        $this->signer = null;

        return $this;
    }

    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        if ($this->signer === null) {
            $this->signer = new Signer($this->headers['alg'], $this->key, $this->passphrase);
        }

        return $this->signer;
    }

    public function setAudience(string $audience): JWTBuilder
    {
        $audiences = $this->claims[RegisteredClaims::AUDIENCE] ?? [];

        if (!\in_array($audience, $audiences, true)) {
            $audiences[] = $audience;

            $this->claims[RegisteredClaims::AUDIENCE] = $audiences;
        }

        return $this;
    }

    public function setExpiresAt(\DateTimeInterface $expiration): JWTBuilder
    {
        $this->claims[RegisteredClaims::EXPIRATION_TIME] = $this->convertDate($expiration);

        return $this;
    }

    public function setIdentifier(string $id): JWTBuilder
    {
        $this->claims[RegisteredClaims::ID] = $id;

        return $this;
    }

    public function setIssuedAt(\DateTimeInterface $issuedAt): JWTBuilder
    {
        $this->claims[RegisteredClaims::ISSUED_AT] = $this->convertDate($issuedAt);

        return $this;
    }

    public function setIssuer(string $issuer): JWTBuilder
    {
        $this->claims[RegisteredClaims::ISSUER] = $issuer;

        return $this;
    }

    public function setNotBefore(\DateTimeInterface $notBefore): JWTBuilder
    {
        $this->claims[RegisteredClaims::NOT_BEFORE] = $this->convertDate($notBefore);

        return $this;
    }

    public function setSubject(string $subject): JWTBuilder
    {
        $this->claims[RegisteredClaims::SUBJECT] = $subject;

        return $this;
    }

    public function setHeader(string $name, $value): JWTBuilder
    {
        if ($name === 'alg') {
            return $this->setAlgorithm($value);
        }

        $this->headers[$name] = $value;

        return $this;
    }

    public function setClaim(string $name, $value): JWTBuilder
    {
        if (\in_array($name, RegisteredClaims::ALL, true)) {
            throw new \InvalidArgumentException('You should use the correct methods to set registered claims');
        }

        $this->claims[$name] = $value;

        return $this;
    }

    public function getClaim(string $name)
    {
        return $this->claims[$name] ?? null;
    }

    public function build(): string
    {
        if (
            isset($this->claims[RegisteredClaims::AUDIENCE][0]) &&
            !isset($this->claims[RegisteredClaims::AUDIENCE][1])
        ) {
            $this->claims[RegisteredClaims::AUDIENCE] = $this->claims[RegisteredClaims::AUDIENCE][0];
        }

        $encodedHeaders = $this->encode($this->headers);
        $encodedClaims = $this->encode($this->claims);

        $payload = $encodedHeaders . '.' . $encodedClaims;
        $signature = $this->getSigner()->sign($payload);

        return $payload . '.' . Base64Url::encode($signature);
    }

    protected function convertDate(\DateTimeInterface $date): string
    {
        $seconds = $date->format('U');
        $microseconds = $date->format('u');

        if ((int) $microseconds === 0) {
            return (int) $seconds;
        }

        return $seconds . '.' . $microseconds;
    }

    protected function encode(array $items): string
    {
        return Base64Url::encode(
            \json_encode($items)
        );
    }
}