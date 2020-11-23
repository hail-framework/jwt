<?php

namespace Hail\Jwt\Util\Calculator;


class BcMathCalculator extends Calculator
{
    public function add(string $a, string $b) : string
    {
        return \bcadd($a, $b, 0);
    }

    public function sub(string $a, string $b) : string
    {
        return \bcsub($a, $b, 0);
    }

    public function mul(string $a, string $b) : string
    {
        return \bcmul($a, $b, 0);
    }

    public function modPow(string $base, string $exp, string $mod) : string
    {
        return \bcpowmod($base, $exp, $mod, 0);
    }

    public function divQ(string $a, string $b) : string
    {
        return \bcdiv($a, $b, 0);
    }

    public function divR(string $a, string $b): string
    {
        return \bcmod($a, $b);
    }

    public function divQR(string $a, string $b) : array
    {
        $q = \bcdiv($a, $b, 0);
        $r = \bcmod($a, $b);

        return [$q, $r];
    }
}