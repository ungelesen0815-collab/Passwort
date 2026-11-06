<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../PasswordGenerator.php';

class PasswordGeneratorTest extends TestCase
{
    private PasswordGenerator $generator;

    protected function setUp(): void
    {
        $this->generator = new PasswordGenerator();
    }

    public function testDefaultPasswordGeneration(): void
    {
        $password = $this->generator->generate();
        $this::assertEquals(PasswordGenerator::DEFAULT_LENGTH, strlen($password));
    }

    public function testCustomLengthPasswordGeneration(): void
    {
        $password = $this->generator->generate(24);
        $this::assertEquals(24, strlen($password));
    }

    public function testMinLengthPasswordGeneration(): void
    {
        $password = $this->generator->generate(PasswordGenerator::MIN_LENGTH);
        $this::assertEquals(PasswordGenerator::MIN_LENGTH, strlen($password));
    }

    public function testMaxLengthPasswordGeneration(): void
    {
        $password = $this->generator->generate(PasswordGenerator::MAX_LENGTH);
        $this::assertEquals(PasswordGenerator::MAX_LENGTH, strlen($password));
    }

    public function testTooShortLengthThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->generator->generate(3);
    }

    public function testTooLongLengthThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->generator->generate(129);
    }

    public function testNumbersOnlyPassword(): void
    {
        $options = [
            'uppercase' => false,
            'lowercase' => false,
            'numbers'   => true,
            'special'   => false,
        ];

        $password = $this->generator->generate(20, $options);
        $this::assertEquals(20, strlen($password));
        $this::assertMatchesRegularExpression('/^[0-9]+$/', $password);
    }

    public function testUppercaseOnlyPassword(): void
    {
        $options = [
            'uppercase' => true,
            'lowercase' => false,
            'numbers'   => false,
            'special'   => false,
        ];

        $password = $this->generator->generate(20, $options);
        $this::assertEquals(20, strlen($password));
        $this::assertMatchesRegularExpression('/^[A-Z]+$/', $password);
    }

    public function testLowercaseOnlyPassword(): void
    {
        $options = [
            'uppercase' => false,
            'lowercase' => true,
            'numbers'   => false,
            'special'   => false,
        ];

        $password = $this->generator->generate(20, $options);
        $this::assertEquals(20, strlen($password));
        $this::assertMatchesRegularExpression('/^[a-z]+$/', $password);
    }

    public function testNoCharacterSetSelectedThrowsException(): void
    {
        $options = [
            'uppercase' => false,
            'lowercase' => false,
            'numbers'   => false,
            'special'   => false,
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->generator->generate(16, $options);
    }

    public function testExcludeAmbiguousCharacters(): void
    {
        $options = [
            'uppercase' => true,
            'lowercase' => true,
            'numbers'   => true,
            'special'   => true,
            'exclude_ambiguous' => true,
        ];

        for ($i = 0; $i < 20; $i++) {
            $password = $this->generator->generate(32, $options);
            $this::assertDoesNotMatchRegularExpression('/[0O1lI]/', $password);
        }
    }

    public function testGuaranteedInclusionOfAllActiveCharacterSets(): void
    {
        $options = [
            'uppercase' => true,
            'lowercase' => true,
            'numbers'   => true,
            'special'   => true,
        ];

        for ($i = 0; $i < 10; $i++) {
            $password = $this->generator->generate(8, $options);
            $this::assertMatchesRegularExpression('/[A-Z]/', $password, 'Should contain at least 1 uppercase letter');
            $this::assertMatchesRegularExpression('/[a-z]/', $password, 'Should contain at least 1 lowercase letter');
            $this::assertMatchesRegularExpression('/[0-9]/', $password, 'Should contain at least 1 number');
            $this::assertMatchesRegularExpression('/[' . preg_quote(PasswordGenerator::CHAR_SPECIAL, '/') . ']/', $password, 'Should contain at least 1 special character');
        }
    }

    public function testExactSpecialCharacterCount(): void
    {
        $options = [
            'uppercase' => true,
            'lowercase' => true,
            'numbers'   => true,
            'special'   => true,
            'special_count' => 3,
        ];

        for ($i = 0; $i < 10; $i++) {
            $password = $this->generator->generate(16, $options);
            $this::assertEquals(16, strlen($password));

            // Count special characters
            $specialChars = str_split(PasswordGenerator::CHAR_SPECIAL);
            $passwordChars = str_split($password);
            $count = 0;
            foreach ($passwordChars as $char) {
                if (in_array($char, $specialChars, true)) {
                    $count++;
                }
            }
            $this::assertEquals(3, $count, 'Should contain exactly 3 special characters');
        }
    }

    public function testSpecialCountExceedsLengthThrowsException(): void
    {
        $options = [
            'uppercase' => true,
            'lowercase' => true,
            'numbers'   => true,
            'special'   => true,
            'special_count' => 17,
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->generator->generate(16, $options);
    }

    public function testGenerateRandomUsername(): void
    {
        $username = $this->generator->generateUsername([
            'mode' => 'random',
            'separator' => '-',
            'include_number' => true,
            'capitalize' => false,
        ]);

        $this::assertMatchesRegularExpression('/^[a-z]+-[a-z]+-[0-9]{3,4}$/', $username);
    }

    public function testGenerateCapitalizedUsernameWithoutNumber(): void
    {
        $username = $this->generator->generateUsername([
            'mode' => 'random',
            'separator' => '_',
            'include_number' => false,
            'capitalize' => true,
        ]);

        $this::assertMatchesRegularExpression('/^[A-Z][a-z]+_[A-Z][a-z]+$/', $username);
    }

    public function testGenerateEmailAlias(): void
    {
        $alias = $this->generator->generateUsername([
            'mode' => 'alias',
            'base_email' => 'max.mustermann@example.com',
            'alias_tag' => 'GitHub',
        ]);

        $this::assertMatchesRegularExpression('/^max\.mustermann\+github-[a-z0-9]{6}@example\.com$/', $alias);
    }

    public function testGenerateEmailAliasThrowsOnInvalidEmail(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->generator->generateEmailAlias('not-an-email', 'shop');
    }
}
