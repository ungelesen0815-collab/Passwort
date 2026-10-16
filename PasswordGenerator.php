<?php

class PasswordGenerator
{
    public const DEFAULT_LENGTH = 16;
    public const MIN_LENGTH = 4;
    public const MAX_LENGTH = 128;

    public const CHAR_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    public const CHAR_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
    public const CHAR_NUMBERS   = '0123456789';
    public const CHAR_SPECIAL   = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    public const CHAR_AMBIGUOUS = '0O1lI';

    /**
     * Generate a random password based on length and options.
     *
     * @param int $length Desired length of password
     * @param array $options Options array:
     *   - 'uppercase' (bool): Include A-Z (default true)
     *   - 'lowercase' (bool): Include a-z (default true)
     *   - 'numbers'   (bool): Include 0-9 (default true)
     *   - 'special'   (bool): Include special characters (default true)
     *   - 'exclude_ambiguous' (bool): Exclude ambiguous chars like 0, O, 1, l, I (default false)
     * @return string
     * @throws InvalidArgumentException
     */
    public function generate(int $length = self::DEFAULT_LENGTH, array $options = []): string
    {
        if ($length < self::MIN_LENGTH || $length > self::MAX_LENGTH) {
            throw new InvalidArgumentException("Password length must be between " . self::MIN_LENGTH . " and " . self::MAX_LENGTH . ".");
        }

        $useUppercase = (bool)($options['uppercase'] ?? true);
        $useLowercase = (bool)($options['lowercase'] ?? true);
        $useNumbers   = (bool)($options['numbers'] ?? true);
        $useSpecial   = (bool)($options['special'] ?? true);
        $excludeAmbiguous = (bool)($options['exclude_ambiguous'] ?? false);

        $sets = [];

        if ($useUppercase) {
            $set = self::CHAR_UPPERCASE;
            if ($excludeAmbiguous) {
                $set = $this->removeAmbiguous($set);
            }
            if ($set !== '') {
                $sets['uppercase'] = $set;
            }
        }

        if ($useLowercase) {
            $set = self::CHAR_LOWERCASE;
            if ($excludeAmbiguous) {
                $set = $this->removeAmbiguous($set);
            }
            if ($set !== '') {
                $sets['lowercase'] = $set;
            }
        }

        if ($useNumbers) {
            $set = self::CHAR_NUMBERS;
            if ($excludeAmbiguous) {
                $set = $this->removeAmbiguous($set);
            }
            if ($set !== '') {
                $sets['numbers'] = $set;
            }
        }

        if ($useSpecial) {
            $set = self::CHAR_SPECIAL;
            if ($excludeAmbiguous) {
                $set = $this->removeAmbiguous($set);
            }
            if ($set !== '') {
                $sets['special'] = $set;
            }
        }

        if (empty($sets)) {
            throw new InvalidArgumentException("At least one character set must be selected.");
        }

        $passwordChars = [];

        // Guaranteed inclusion of at least 1 char from each selected set
        foreach ($sets as $set) {
            $passwordChars[] = $set[random_int(0, strlen($set) - 1)];
        }

        // Combine all selected character sets into pool
        $allChars = implode('', $sets);

        // Fill remaining slots
        while (count($passwordChars) < $length) {
            $passwordChars[] = $allChars[random_int(0, strlen($allChars) - 1)];
        }

        // Cryptographically secure shuffle using Fisher-Yates
        $count = count($passwordChars);
        for ($i = $count - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            $temp = $passwordChars[$i];
            $passwordChars[$i] = $passwordChars[$j];
            $passwordChars[$j] = $temp;
        }

        return implode('', $passwordChars);
    }

    private function removeAmbiguous(string $set): string
    {
        $ambiguousChars = str_split(self::CHAR_AMBIGUOUS);
        return str_replace($ambiguousChars, '', $set);
    }
}
