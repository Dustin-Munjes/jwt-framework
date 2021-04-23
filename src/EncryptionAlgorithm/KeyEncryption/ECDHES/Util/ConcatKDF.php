<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util;

use Base64Url\Base64Url;
use InvalidArgumentException;

/**
 * @internal
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.6.2
 */
class ConcatKDF
{
    /**
     * Key Derivation Function.
     *
     * @param string $Z                   Shared secret
     * @param string $algorithm           Encryption algorithm
     * @param int    $encryption_key_size Size of the encryption key
     * @param string $apu                 Agreement PartyUInfo (information about the producer)
     * @param string $apv                 Agreement PartyVInfo (information about the recipient)
     */
    public static function generate(string $Z, string $algorithm, int $encryption_key_size, string $apu = '', string $apv = ''): string
    {
        $apu = !self::isEmpty($apu) ? Base64Url::decode($apu) : '';
        $apv = !self::isEmpty($apv) ? Base64Url::decode($apv) : '';

        $hash_len = strcmp($algorithm, "ECDH-ES+A128KW") == 0 ? 128 : 256;

        $repetitions = $encryption_key_size / $hash_len;
        $derivedKey = "";
        for ($i = 1; $i <= $repetitions; $i++) {
            $encryption_segments = [
                self::toInt32Bits($i),                                       // Round number
                $Z,                                                          // Z (shared secret)
                self::toInt32Bits(mb_strlen($algorithm, '8bit')).$algorithm, // Size of algorithm's name and algorithm
                self::toInt32Bits(mb_strlen($apu, '8bit')).$apu,             // PartyUInfo
                self::toInt32Bits(mb_strlen($apv, '8bit')).$apv,             // PartyVInfo
                self::toInt32Bits($encryption_key_size),                     // SuppPubInfo (the encryption key size)
                '',                                                          // SuppPrivInfo
            ];
            $input = implode('', $encryption_segments);
            $derivedKey = $derivedKey . hash('sha256', $input, true);
        }
        return $derivedKey;
    }

    /**
     * Convert an integer into a 32 bits string.
     *
     * @param int $value Integer to convert
     */
    private static function toInt32Bits(int $value): string
    {
        $result = hex2bin(str_pad(dechex($value), 8, '0', STR_PAD_LEFT));
        if (false === $result) {
            throw new InvalidArgumentException('Invalid result');
        }

        return $result;
    }

    private static function isEmpty(?string $value): bool
    {
        return null === $value || '' === $value;
    }
}
