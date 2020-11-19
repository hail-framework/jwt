<?php

namespace Hail\Jwt\Util\Calculator;

use Hail\Singleton\SingletonTrait;

\defined('GMP_EXTENSION') || \define('GMP_EXTENSION', \extension_loaded('gmp'));
if (!GMP_EXTENSION) {
    \defined('BCMATH_EXTENSION') || \define('BCMATH_EXTENSION', \extension_loaded('bcmath'));
}

abstract class Calculator
{
    use SingletonTrait;

    /**
     * The alphabet for converting from and to base 2 to 36, lowercase.
     */
    public const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';

    public static function detect(): Calculator
    {
        switch (true) {
            case GMP_EXTENSION:
                return GmpCalculator::getInstance();

            case BCMATH_EXTENSION:
                return BcMathCalculator::getInstance();

            default:
                return NativeCalculator::getInstance();
        }
    }

    /**
     * Converts a number from an arbitrary base.
     *
     * @param string $number The number, positive or zero, non-empty, case-insensitively validated for the given base.
     * @param int    $base   The base of the number, validated from 2 to 36.
     *
     * @return string The converted number, following the Calculator conventions.
     */
    public function fromBase(string $number, int $base) : string
    {
        $alphabet = self::ALPHABET;

        // remove leading "zeros"
        $number = \ltrim(\strtolower($number), $alphabet[0]);

        if ($number === '') {
            return '0';
        }

        // optimize for "one"
        if ($number === $alphabet[1]) {
            return '1';
        }

        $result = '0';
        $power = '1';

        for ($i = \strlen($number) - 1; $i >= 0; $i--) {
            $index = \strpos($alphabet, $number[$i]);

            if ($index !== 0) {
                $result = $this->add($result, ($index === 1)
                    ? $power
                    : $this->mul($power, (string) $index)
                );
            }

            if ($i !== 0) {
                $power = $this->mul($power, (string) $base);
            }
        }

        return $result;
    }

    /**
     * Converts a number to an arbitrary base.
     *
     * @param string $number The number to convert, following the Calculator conventions.
     * @param int    $base   The base to convert to, validated from 2 to 36.
     *
     * @return string The converted number, lowercase.
     */
    public function toBase(string $number, int $base) : string
    {
        $negative = ($number[0] === '-');

        if ($negative) {
            $number = \substr($number, 1);
        }

        $alphabet = self::ALPHABET;

        if ($number === '0') {
            $number = $alphabet[0];
        } else {

            $baseStr = (string) $base;
            $result = '';

            while ($number !== '0') {
                [$number, $remainder] = $this->divQR($number, $baseStr);
                $remainder = (int) $remainder;

                $result .= $alphabet[$remainder];
            }

            $number = \strrev($result);
        }

        if ($negative) {
            return '-' . $number;
        }

        return $number;
    }

    /**
     * Compares two numbers.
     *
     * @param string $a The first number.
     * @param string $b The second number.
     *
     * @return int [-1, 0, 1] If the first number is less than, equal to, or greater than the second number.
     */
    public function cmp(string $a, string $b) : int
    {
        [$aNeg, $bNeg, $aDig, $bDig] = $this->extract($a, $b);

        if ($aNeg && ! $bNeg) {
            return -1;
        }

        if ($bNeg && ! $aNeg) {
            return 1;
        }

        $aLen = \strlen($aDig);
        $bLen = \strlen($bDig);

        if ($aLen < $bLen) {
            $result = -1;
        } elseif ($aLen > $bLen) {
            $result = 1;
        } else {
            $result = $aDig <=> $bDig;
        }

        return $aNeg ? -$result : $result;
    }

    /**
     * Extracts the sign & digits of the operands.
     *
     * @param string $a The first operand.
     * @param string $b The second operand.
     *
     * @return array{0: bool, 1: bool, 2: string, 3: string} Whether $a and $b are negative, followed by their digits.
     */
    protected function extract(string $a, string $b) : array
    {
        return [
            $aNeg = ($a[0] === '-'),
            $bNeg = ($b[0] === '-'),

            $aNeg ? \substr($a, 1) : $a,
            $bNeg ? \substr($b, 1) : $b,
        ];
    }

    /**
     * Negates a number.
     *
     * @param string $n The number.
     *
     * @return string The negated value.
     */
    public function neg(string $n) : string
    {
        if ($n === '0') {
            return '0';
        }

        if ($n[0] === '-') {
            return \substr($n, 1);
        }

        return '-' . $n;
    }

    /**
     * Adds two numbers.
     *
     * @param string $a The augend.
     * @param string $b The addend.
     *
     * @return string The sum.
     */
    abstract public function add(string $a, string $b) : string;

    /**
     * Subtracts two numbers.
     *
     * @param string $a The minuend.
     * @param string $b The subtrahend.
     *
     * @return string The difference.
     */
    abstract public function sub(string $a, string $b) : string;

    /**
     * Multiplies two numbers.
     *
     * @param string $a The multiplicand.
     * @param string $b The multiplier.
     *
     * @return string The product.
     */
    abstract public function mul(string $a, string $b) : string;

    /**
     * @param string $a
     * @param string $b The modulus; must not be zero.
     *
     * @return string
     */
    abstract public function mod(string $a, string $b) : string;

    /**
     * Raises a number into power with modulo.
     * Algorithm from: https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
     *
     * @param string $base The base number; must be positive or zero.
     * @param string $exp  The exponent; must be positive or zero.
     * @param string $mod  The modulus; must be strictly positive.
     *
     * @return string The power.
     */
    abstract public function modPow(string $base, string $exp, string $mod) : string;

    /**
     * Returns the quotient of the division of two numbers.
     *
     * @param string $a The dividend.
     * @param string $b The divisor, must not be zero.
     *
     * @return string The quotient.
     */
    abstract public function divQ(string $a, string $b) : string;

    /**
     * Returns the remainder of the division of two numbers.
     *
     * @param string $a The dividend.
     * @param string $b The divisor, must not be zero.
     *
     * @return string The remainder.
     */
    abstract public function divR(string $a, string $b): string;

    /**
     * Returns the quotient and remainder of the division of two numbers.
     *
     * @param string $a The dividend.
     * @param string $b The divisor, must not be zero.
     *
     * @return string[] An array containing the quotient and remainder.
     */
    abstract public function divQR(string $a, string $b) : array;
}