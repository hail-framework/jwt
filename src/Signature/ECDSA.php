<?php

namespace Hail\Jwt\Signature;

final class ECDSA extends RSA
{
    protected const KEY_TYPE = \OPENSSL_KEYTYPE_EC;

    protected const JWT_KTY = 'ec';
    protected const JWT_MAP = [
        'x' => 'x',
        'y' => 'y',
        'd' => 'd',
        'curve_name' => 'crv',
    ];

    protected const HASH_LENGTH = [
        'sha256' => 64,
        'sha384' => 96,
        'sha512' => 132,
    ];

    protected const CURVE = [
        'prime256v1' => 'P-256',
        'secp384r1' => 'P-384',
        'secp521r1' => 'P-521',
        'secp256k1' => 'secp256k1'
    ];

    public function sign(string $payload, $key, string $hash): string
    {
        return $this->fromDER(
            parent::sign($payload, $key, $hash),
            $this->getHashLength($hash)
        );
    }

    private function fromDER(string $der, int $partLength): string
    {
        $hex = unpack('H*', $der)[1];
        if (0 !== mb_strpos($hex, '30', 0, '8bit')) { // SEQUENCE
            throw new \InvalidArgumentException('Invalid ASN.1 SEQUENCE');
        }

        if ('81' === \mb_substr($hex, 2, 2, '8bit')) { // LENGTH > 128
            $hex = \mb_substr($hex, 6, null, '8bit');
        } else {
            $hex = \mb_substr($hex, 4, null, '8bit');
        }

        if (0 !== \mb_strpos($hex, '02', 0, '8bit')) { // INTEGER
            throw new \RuntimeException('Invalid ASN.1 INTEGER');
        }

        $Rl = \hexdec(\mb_substr($hex, 2, 2, '8bit'));
        $R = $this->retrievePositiveInteger(\mb_substr($hex, 4, $Rl * 2, '8bit'));
        $R = \str_pad($R, $partLength, '0', STR_PAD_LEFT);

        $hex = \mb_substr($hex, 4 + $Rl * 2, null, '8bit');
        if (0 !== \mb_strpos($hex, '02', 0, '8bit')) { // INTEGER
            throw new \RuntimeException('Invalid ASN.1 INTEGER');
        }

        $Sl = \hexdec(\mb_substr($hex, 2, 2, '8bit'));
        $S = $this->retrievePositiveInteger(\mb_substr($hex, 4, $Sl * 2, '8bit'));
        $S = \str_pad($S, $partLength, '0', STR_PAD_LEFT);

        return \pack('H*', $R . $S);
    }

    /**
     * @param string $data
     *
     * @return string
     */
    private function retrievePositiveInteger(string $data): string
    {
        while (0 === \mb_strpos($data, '00', 0, '8bit') && \mb_substr($data, 2, 2, '8bit') > '7f') {
            $data = \mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }

    public function verify(string $signature, string $payload, $key, string $hash): bool
    {
        return parent::verify(
            $this->toDER($signature, $this->getHashLength($hash)),
            $payload, $key, $hash
        );
    }

    private function toDER(string $signature, int $partLength): string
    {
        $signature = \unpack('H*', $signature)[1];
        if (\mb_strlen($signature, '8bit') !== 2 * $partLength) {
            throw new \InvalidArgumentException('Invalid length.');
        }
        $R = \mb_substr($signature, 0, $partLength, '8bit');
        $S = \mb_substr($signature, $partLength, null, '8bit');

        $R = $this->preparePositiveInteger($R);
        $Rl = \mb_strlen($R, '8bit') / 2;
        $S = $this->preparePositiveInteger($S);
        $Sl = \mb_strlen($S, '8bit') / 2;
        $der = \pack('H*',
            '30' . ($Rl + $Sl + 4 > 128 ? '81' : '') . \dechex($Rl + $Sl + 4)
            . '02' . \dechex($Rl) . $R
            . '02' . \dechex($Sl) . $S
        );

        return $der;
    }

    private function preparePositiveInteger(string $data): string
    {
        if (\mb_substr($data, 0, 2, '8bit') > '7f') {
            return '00' . $data;
        }

        while (0 === \mb_strpos($data, '00', 0, '8bit') && \mb_substr($data, 2, 2, '8bit') <= '7f') {
            $data = \mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }

    public function getJWK($key): array
    {
        $jwk = parent::getJWK($key);
        $jwk['crv'] = $this->getECKeyCurve($jwk['crv']);

        return $jwk;
    }

    private function getHashLength(string $hash): int
    {
        if (!isset(self::HASH_LENGTH[$hash])) {
            throw new \InvalidArgumentException('Unsupported Hash.');
        }

        return self::HASH_LENGTH[$hash];
    }

    private function getECKeyCurve(string $name): string
    {
        if (!isset(self::CURVE[$name])) {
            throw new \InvalidArgumentException('Unsupported Curve Name.');
        }

        return self::CURVE[$name];
    }
}
