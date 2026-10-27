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

        $sets = $this->getAvailableSets($options);

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
        $allCharsLen = strlen($allChars);
        $currentCount = count($passwordChars);
        for ($i = $currentCount; $i < $length; $i++) {
            $passwordChars[] = $allChars[random_int(0, $allCharsLen - 1)];
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

    private function getAvailableSets(array $options): array
    {
        $excludeAmbiguous = (bool)($options['exclude_ambiguous'] ?? false);
        $sets = [];

        $this->addSetIfRequested($sets, 'uppercase', self::CHAR_UPPERCASE, (bool)($options['uppercase'] ?? true), $excludeAmbiguous);
        $this->addSetIfRequested($sets, 'lowercase', self::CHAR_LOWERCASE, (bool)($options['lowercase'] ?? true), $excludeAmbiguous);
        $this->addSetIfRequested($sets, 'numbers',   self::CHAR_NUMBERS,   (bool)($options['numbers'] ?? true),   $excludeAmbiguous);
        $this->addSetIfRequested($sets, 'special',   self::CHAR_SPECIAL,   (bool)($options['special'] ?? true),   $excludeAmbiguous);

        return $sets;
    }

    private function addSetIfRequested(array &$sets, string $key, string $chars, bool $requested, bool $excludeAmbiguous): void
    {
        if ($requested) {
            $set = $chars;
            if ($excludeAmbiguous) {
                $set = $this->removeAmbiguous($set);
            }
            if ($set !== '') {
                $sets[$key] = $set;
            }
        }
    }

    private function removeAmbiguous(string $set): string
    {
        $ambiguousChars = str_split(self::CHAR_AMBIGUOUS);
        return str_replace($ambiguousChars, '', $set);
    }
}
