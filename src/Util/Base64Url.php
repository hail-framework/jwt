<?php

namespace Hail\Jwt\Util;


class Base64Url
{
    /**
     * @param string $data
     * @param bool   $usePadding If true, the "=" padding at end of the encoded value are kept, else it is removed
     *
     * @return string
     */
    public static function encode(string $data, bool $usePadding = false): string
    {
        $encoded = \strtr(\base64_encode($data), '+/', '-_');

        return $usePadding ? $encoded : \rtrim($encoded, '=');
    }

    public static function decode(string $data): string
    {
        return \base64_decode(\strtr($data, '-_', '+/'));
    }
}