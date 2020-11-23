<?php

namespace Hail\Jwt\Util;

class RSA
{
    public const HASH_LENGTH = [
        'sha256' => 32,
        'sha384' => 46,
        'sha512' => 64,
    ];

    public static function getMGF1($mgfSeed, $maskLen, $hash)
    {
        $t = '';
        $count = \ceil($maskLen / self::getHashLength($hash));
        for ($i = 0; $i < $count; ++$i) {
            $c = \pack('N', $i);
            $t .= \hash($hash, $mgfSeed . $c, true);
        }

        return \mb_substr($t, 0, $maskLen, '8bit');
    }

    public static function getHashLength($hash)
    {
        if (!isset(self::HASH_LENGTH[$hash])) {
            throw new \InvalidArgumentException('Unsupported Hash.');
        }

        return self::HASH_LENGTH[$hash];
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem.
     * Operation with primes 'p' and 'q' is appox. 2x faster.
     *
     * @param array $key
     * @param BigInteger $c
     *
     * @return BigInteger
     */
    public static function exponentiate(array $key, BigInteger $c): BigInteger
    {
        if ($c->compare($key['n']) > 0 || $c->compare(BigInteger::zero()) < 0) {
            throw new \RuntimeException('RSA key invalid');
        }

        if (!isset($key['d'], $key['p'], $key['q'], $key['dmp1'], $key['dmq1'], $key['iqmp'])) {
            return $c->modPow($key['e'], $key['n']);
        }

        [
            'p' => $p,
            'q' => $q,
            'dmp1' => $dP,
            'dmq1' => $dQ,
            'iqmp' => $qInv,
        ] = $key;

        $m1 = $c->modPow($dP, $p);
        $m2 = $c->modPow($dQ, $q);
        $h = $qInv->multiply($m1->subtract($m2)->add($p))->mod($p);

        return $m2->add($h->multiply($q));
    }

    public static function getKeyDetails($key): array
    {
        $details = \openssl_pkey_get_details($key);
        if (!isset($details['rsa'])) {
            throw new \UnexpectedValueException("Invalid rsa key");
        }

        $parts = $details['rsa'];
        $modulusLen = \mb_strlen($parts['n'], '8bit');

        foreach ($parts as $k => &$v) {
            $v = self::convertOctetStringToInteger($v);
        }

        return [$parts, $modulusLen];
    }

    public static function convertOctetStringToInteger(string $x): BigInteger
    {
        $data = bin2hex($x);

        return BigInteger::fromBase($data, 16);
    }

    public static function convertIntegerToOctetString(BigInteger $x, int $xLen): string
    {
        $s = $x->toBytes();
        if (\mb_strlen($s, '8bit') > $xLen) {
            throw new \RuntimeException('Invalid length.');
        }

        return \str_pad($s, $xLen, \chr(0), STR_PAD_LEFT);
    }
}
