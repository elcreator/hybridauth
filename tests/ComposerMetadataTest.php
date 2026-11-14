<?php

namespace HybridauthTest;

use PHPUnit\Framework\TestCase;

class ComposerMetadataTest extends TestCase
{
    public function testForkHasDistinctPackageNameAndVersionScopedReplacement(): void
    {
        $metadata = json_decode(file_get_contents(dirname(__DIR__) . '/composer.json'), true);
        $this->assertSame('elcreator/hybridauth', $metadata['name']);
        $this->assertSame('self.version', $metadata['replace']['hybridauth/hybridauth']);
        $this->assertSame('src/', $metadata['autoload']['psr-4']['Hybridauth\\']);
    }
}
