<?php

use OliverHader\SecretsKms\Cipher;
use OliverHader\SecretsKms\KeyEntry;
use OliverHader\SecretsKms\KeyPair;
use OliverHader\SecretsKms\Manager;
use OliverHader\SecretsKms\Storage;

require_once 'vendor/autoload.php';

$storage = new Storage(__DIR__. '/secrets.json');

$prodKeys = KeyPair::fromSeed('SeCr3T:Production');
$devKeys = KeyPair::fromSeed('SeCr3T:Development');
$devKeyEntry = new KeyEntry($devKeys->getPublicKey(), 'Development');

echo 'Prod Fingerprint: ' . $prodKeys->getPublicKey()->getFingerprint() . PHP_EOL;
echo 'Dev Fingerprint:  ' . $devKeys->getPublicKey()->getFingerprint() . PHP_EOL;

$manager = new Manager($prodKeys, $storage);
if (!$manager->hasDomain('typo3/user-settings')) {
    $manager->addPublicKeys($devKeyEntry);
    $manager->createDomain('typo3/user-settings');
}
$cipher = new Cipher($manager);
$sealed = $cipher->sealWithDomainDataKey('typo3/user-settings', 'my-secret-value');

$manager = new Manager($devKeys, $storage);
$cipher = new Cipher($manager);
$unsealed = $cipher->unsealWithDomainDataKey('typo3/user-settings', $sealed);

echo 'Sealed:   ' . $sealed . PHP_EOL;
echo 'Unsealed: ' . $unsealed . PHP_EOL;

echo 'New KeyPair: ' . KeyPair::generate()->getPublicKey()->getMultibase() . PHP_EOL;