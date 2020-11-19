<?php

namespace Hail\Jwt\Util;

use Hail\Jwt\Util\Calculator\Calculator;

/**
 * @internal
 */
final class BigInteger
{
    private static $zero;

    /**
     * The value, as a string of digits with optional leading minus sign.
     *
     * No leading zeros must be present.
     * No leading minus sign must be present if the number is zero.
     *
     * @var string
     */
    private $value;

    /**
     * @var Calculator
     */
    private static $calculator;

    /**
     * Protected constructor. Use a factory method to obtain an instance.
     *
     * @param string $value A string of digits, with optional leading minus sign.
     */
    protected function __construct(string $value)
    {
        $this->value = $value;

        if (!self::$calculator) {
            self::$calculator = Calculator::detect();
        }
    }

    /**
     * Converts a BigInteger to a binary string.
     */
    public function toBytes(): string
    {
        if ($this->value === '0') {
            return '';
        }

        $temp = $this->toBase(16);
        $temp = 0 !== (\mb_strlen($temp, '8bit') & 1) ? '0' . $temp : $temp;
        $temp = \hex2bin($temp);

        return \ltrim($temp, chr(0));
    }

    /**
     * Creates a number from a string in a given base.
     *
     * The string can optionally be prefixed with the `+` or `-` sign.
     *
     * Bases greater than 36 are not supported by this method, as there is no clear consensus on which of the lowercase
     * or uppercase characters should come first. Instead, this method accepts any base up to 36, and does not
     * differentiate lowercase and uppercase characters, which are considered equal.
     *
     * For bases greater than 36, and/or custom alphabets, use the fromArbitraryBase() method.
     *
     * @param string $number The number to convert, in the given base.
     * @param int $base The base of the number, between 2 and 36.
     *
     * @return self
     *
     * @psalm-pure
     */
    public static function fromBase(string $number, int $base): self
    {
        if ($number === '') {
            throw new \InvalidArgumentException('The number cannot be empty.');
        }

        if ($base < 2 || $base > 36) {
            throw new \OutOfRangeException(\sprintf('Base %d is not in range 2 to 36.', $base));
        }

        if ($number[0] === '-') {
            $sign = '-';
            $number = \substr($number, 1);
        } elseif ($number[0] === '+') {
            $sign = '';
            $number = \substr($number, 1);
        } else {
            $sign = '';
        }

        if ($number === '') {
            throw new \InvalidArgumentException('The number cannot be empty.');
        }

        $number = \ltrim($number, '0');

        if ($number === '') {
            // The result will be the same in any base, avoid further calculation.
            return self::zero();
        }

        if ($number === '1') {
            // The result will be the same in any base, avoid further calculation.
            return new self($sign . '1');
        }

        $pattern = '/[^' . \substr(Calculator::ALPHABET, 0, $base) . ']/';

        if (\preg_match($pattern, \strtolower($number), $matches) === 1) {
            throw new \InvalidArgumentException(\sprintf('"%s" is not a valid character in base %d.', $matches[0], $base));
        }

        if ($base === 10) {
            // The number is usable as is, avoid further calculation.
            return new self($sign . $number);
        }

        $new = clone self::zero();
        $new->value = $sign . self::$calculator->fromBase($number, $base);

        return $new;
    }

    /**
     * Returns a BigInteger representing zero.
     *
     * @return self
     */
    public static function zero(): self
    {
        if (self::$zero === null) {
            self::$zero = new self('0');
        }

        return self::$zero;
    }

    /**
     * Returns a string representation of this number in the given base.
     *
     * The output will always be lowercase for bases greater than 10.
     *
     * @param int $base
     *
     * @return string
     *
     * @throws \OutOfRangeException If the base is out of range.
     */
    public function toBase(int $base): string
    {
        if ($base === 10) {
            return $this->value;
        }

        if ($base < 2 || $base > 36) {
            throw new \OutOfRangeException(\sprintf('Base %d is out of range [2, 36]', $base));
        }

        return self::$calculator->toBase($this->value, $base);
    }

    /**
     * Compares this number to the given one.
     *
     * @param self $that
     *
     * @return int [-1,0,1] If `$this` is lower than, equal to, or greater than `$that`.
     */
    public function compare(self $that): int
    {
        return self::$calculator->cmp($this->value, $that->value);
    }

    /**
     * Returns this number raised into power with modulo.
     *
     * This operation only works on positive numbers.
     *
     * @param self $exp The exponent. Must be positive or zero.
     * @param self $mod The modulus. Must be strictly positive.
     *
     * @return self
     */
    public function modPow(self $exp, self $mod): self
    {
        if ($this->value[0] === '-' || $exp->value[0] === '-' || $mod->value[0] === '-') {
            throw new \InvalidArgumentException('The operands cannot be negative.');
        }

        if ($mod->value === '0') {
            throw new \RuntimeException('The modulus must not be zero.');
        }

        $result = self::$calculator->modPow($this->value, $exp->value, $mod->value);

        return new self($result);
    }

    /**
     * Returns the product of this number and the given one.
     *
     * @param self $that The multiplier. Must be convertible to a BigInteger.
     *
     * @return self The result.
     */
    public function multiply(self $that): self
    {
        if ($that->value === '1') {
            return $this;
        }

        if ($this->value === '1') {
            return $that;
        }

        $value = self::$calculator->mul($this->value, $that->value);

        return new self($value);
    }

    /**
     * Returns the difference of this number and the given one.
     *
     * @param self $that The number to subtract. Must be convertible to a BigInteger.
     *
     * @return self The result.
     */
    public function subtract(self $that): self
    {
        if ($that->value === '0') {
            return $this;
        }

        $value = self::$calculator->sub($this->value, $that->value);

        return new self($value);
    }

    /**
     * Returns the sum of this number and the given one.
     *
     * @param self $that The number to add. Must be convertible to a BigInteger.
     *
     * @return self The result.
     */
    public function add(self $that): self
    {
        if ($that->value === '0') {
            return $this;
        }

        if ($this->value === '0') {
            return $that;
        }

        $value = self::$calculator->add($this->value, $that->value);

        return new self($value);
    }

    /**
     * Returns the modulo of this number and the given one.
     *
     * The modulo operation yields the same result as the remainder operation when both operands are of the same sign,
     * and may differ when signs are different.
     *
     * The result of the modulo operation, when non-zero, has the same sign as the divisor.
     *
     * @param self $that The divisor. Must be convertible to a BigInteger.
     *
     * @return self
     */
    public function mod(self $that): self
    {
        if ($that->value === '0') {
            throw new \RuntimeException('The modulus must not be zero.');
        }

        $value = self::$calculator->mod($this->value, $that->value);

        return new self($value);
    }
}
