<?php

namespace Hail\Jwt\Util\Calculator;


class GmpCalculator extends Calculator
{
    public function fromBase(string $number, int $base) : string
    {
        return \gmp_strval(\gmp_init($number, $base));
    }

    public function toBase(string $number, int $base) : string
    {
        return \gmp_strval($number, $base);
    }

    public function add(string $a, string $b) : string
    {
        return \gmp_strval(\gmp_add($a, $b));
    }

    public function sub(string $a, string $b) : string
    {
        return \gmp_strval(\gmp_sub($a, $b));
    }

    public function mul(string $a, string $b) : string
    {
        return \gmp_strval(\gmp_mul($a, $b));
    }

    public function mod(string $a, string $b) : string
    {
        return \gmp_strval(\gmp_mod($a, $b));
    }

    public function modPow(string $base, string $exp, string $mod) : string
    {
        return \gmp_strval(\gmp_powm($base, $exp, $mod));
    }

    public function divQ(string $a, string $b) : string
    {
        return \gmp_strval(\gmp_div_q($a, $b));
    }

    public function divR(string $a, string $b): string
    {
        return \gmp_strval(\gmp_div_r($a, $b));
    }

    public function divQR(string $a, string $b) : array
    {
        [$q, $r] = \gmp_div_qr($a, $b);

        return [
            \gmp_strval($q),
            \gmp_strval($r)
        ];
    }
}