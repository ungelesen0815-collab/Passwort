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

    public const USERNAME_ADJECTIVES = [
        'silent', 'swift', 'cyber', 'lunar', 'solar', 'amber', 'crimson', 'cobalt',
        'emerald', 'frosty', 'golden', 'hidden', 'iron', 'misty', 'neon', 'noble',
        'quantum', 'rapid', 'shadow', 'silver', 'stellar', 'stormy', 'velvet', 'vivid'
    ];

    public const USERNAME_NOUNS = [
        'falcon', 'phoenix', 'tiger', 'orca', 'wolf', 'lynx', 'raven', 'viper',
        'comet', 'nebula', 'pulsar', 'vertex', 'cipher', 'vector', 'shield', 'anchor',
        'beacon', 'forge', 'harbor', 'matrix', 'nexus', 'prism', 'quartz', 'zephyr'
    ];

    /**
     * Generate a random password based on length and options.
     *
     * @param int $length Desired length of password
     * @param array $options Options array:
     *   - 'uppercase' (bool): Include A-Z (default true)
     *   - 'lowercase' (bool): Include a-z (default true)
     *   - 'numbers'   (bool): Include 0-9 (default true)
     *   - 'special'   (bool): Include special characters (default true)
     *   - 'special_count' (int|null): Exact number of special characters to include. Requires 'special' to be true.
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

        $specialCount = $options['special_count'] ?? null;
        if ($specialCount !== null) {
            $specialCount = (int)$specialCount;
            if ($specialCount < 0) {
                throw new InvalidArgumentException("Special character count cannot be negative.");
            }
            if ($specialCount > $length) {
                throw new InvalidArgumentException("Special character count cannot exceed password length.");
            }
            if ($specialCount > 0 && !isset($sets['special'])) {
                throw new InvalidArgumentException("Special characters must be enabled to set a special character count.");
            }
        }

        $passwordChars = [];

        // Exact special characters if requested
        if ($specialCount !== null && isset($sets['special'])) {
            $specialSet = $sets['special'];
            $specialSetLen = strlen($specialSet);
            for ($i = 0; $i < $specialCount; $i++) {
                $passwordChars[] = $specialSet[random_int(0, $specialSetLen - 1)];
            }

            // If we have remaining length and sets, but all remaining length is zero, we handle it below
            // Remove special from sets for guaranteed inclusion and fill if exact count was used
            $fillSets = $sets;
            unset($fillSets['special']);

            // Check if we need to fill other required characters, but don't have space
            if (count($fillSets) > $length - $specialCount) {
                throw new InvalidArgumentException("Not enough length to include at least one character from each selected set.");
            }
        } else {
            $fillSets = $sets;
        }

        // Guaranteed inclusion of at least 1 char from each selected set (remaining)
        foreach ($fillSets as $set) {
            $passwordChars[] = $set[random_int(0, strlen($set) - 1)];
        }

        if (empty($fillSets) && $specialCount !== null && count($passwordChars) < $length) {
             throw new InvalidArgumentException("Only special characters selected but count is less than length.");
        }

        // Combine all remaining character sets into pool
        $allChars = implode('', $fillSets);
        $allCharsLen = strlen($allChars);

        // Fill remaining slots
        if ($allCharsLen > 0) {
            $currentCount = count($passwordChars);
            for ($i = $currentCount; $i < $length; $i++) {
                $passwordChars[] = $allChars[random_int(0, $allCharsLen - 1)];
            }
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

    /**
     * Generate a random readable username or email plus-addressing alias.
     *
     * @param array $options
     *   - 'mode' (string): 'random' (default) or 'alias'
     *   - 'separator' (string): '-', '_', '.', or '' (default '-')
     *   - 'include_number' (bool): Append a 3-4 digit random number (default true)
     *   - 'capitalize' (bool): Capitalize words (default false)
     *   - 'base_email' (string): Required when mode === 'alias'
     *   - 'alias_tag' (string): Optional tag for plus-addressing (e.g. 'shop')
     * @return string
     * @throws InvalidArgumentException
     */
    public function generateUsername(array $options = []): string
    {
        $mode = $options['mode'] ?? 'random';

        if ($mode === 'alias') {
            $baseEmail = trim((string)($options['base_email'] ?? ''));
            $aliasTag = trim((string)($options['alias_tag'] ?? ''));
            return $this->generateEmailAlias($baseEmail, $aliasTag);
        }

        $separator = (string)($options['separator'] ?? '-');
        if (!in_array($separator, ['-', '_', '.', ''], true)) {
            $separator = '-';
        }
        $includeNumber = array_key_exists('include_number', $options) ? (bool)$options['include_number'] : true;
        $capitalize = !empty($options['capitalize']);

        $adj = self::USERNAME_ADJECTIVES[random_int(0, count(self::USERNAME_ADJECTIVES) - 1)];
        $noun = self::USERNAME_NOUNS[random_int(0, count(self::USERNAME_NOUNS) - 1)];

        if ($capitalize) {
            $adj = ucfirst($adj);
            $noun = ucfirst($noun);
        }

        $username = $adj . $separator . $noun;
        if ($includeNumber) {
            $num = (string)random_int(100, 9999);
            $username .= $separator . $num;
        }

        return $username;
    }

    /**
     * Generate a plus-addressing email alias (e.g. user+shop-a8f3k2@example.com).
     */
    public function generateEmailAlias(string $baseEmail, string $serviceTag = '', int $tokenLength = 6): string
    {
        $baseEmail = trim($baseEmail);
        if ($baseEmail === '' || !filter_var($baseEmail, FILTER_VALIDATE_EMAIL) || !str_contains($baseEmail, '@')) {
            throw new InvalidArgumentException("Bitte geben Sie eine gültige Basis-E-Mail-Adresse ein.");
        }

        [$localPart, $domainPart] = explode('@', $baseEmail, 2);
        // Strip any existing +tag from localPart
        if (str_contains($localPart, '+')) {
            $localPart = explode('+', $localPart, 2)[0];
        }

        $cleanTag = preg_replace('/[^a-zA-Z0-9_-]/', '', strtolower(trim($serviceTag)));
        $alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
        $alphaLen = strlen($alphabet);
        $token = '';
        $len = max(4, min(16, $tokenLength));
        for ($i = 0; $i < $len; $i++) {
            $token .= $alphabet[random_int(0, $alphaLen - 1)];
        }

        $plusPart = $cleanTag !== '' ? ($cleanTag . '-' . $token) : $token;
        return $localPart . '+' . $plusPart . '@' . $domainPart;
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
