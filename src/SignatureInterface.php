<?php


namespace Hail\Jwt;


interface SignatureInterface
{
    public function available(): bool;

    public function getPublicKey(string $content);

    public function getPrivateKey(string $content, string $passphrase);

    public function sign(string $payload, $key, string $hash): string;

    public function verify(string $signature, string $payload, $key, string $hash): bool;

    public function getJWK($key): array;
}