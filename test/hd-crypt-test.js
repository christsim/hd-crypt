var assert = require('assert');

var hdCrypt = require('../src/hd-crypt.js');
var bip39 = require('bip39');
var HDKey = require('hdkey');

function createHdKey() {
    var mnemonic = bip39.generateMnemonic();
    var hdkey = HDKey.fromMasterSeed(bip39.mnemonicToSeedHex(mnemonic));
    return hdkey.toJSON();
}

describe('hdCrypt', () => {
    it('should generate same key for both parties', () => {
        var hdKey1 = createHdKey();
        var hdKey2 = createHdKey();
        var path = 'm/0/2/3/45/1';

        var shared1 = hdCrypt.genSharedKey(hdKey1.xpriv, hdKey2.xpub, path);
        var shared2 = hdCrypt.genSharedKey(hdKey2.xpriv, hdKey1.xpub, path);
        
        assert.deepEqual(shared1, shared2);
    });

    it('should be able to decrypt and encrypt using shared keys', () => {
        // 1
        var xprv1 = 'xprv9s21ZrQH143K4PKh3KrNbTu896eT6j2cE6Uaj2T3728vca21EdDitGcytYpPL8jWWA7WoKTtTzaPAoXmFqcsiWdJutsxyuc421y9dzHaN48';
        var xpub1 = 'xpub661MyMwAqRbcGsQA9MPNxbqrh8UwWBkTbKQBXQrefMfuVNM9nAXyS4wTjsRcVc6bGtrXPTP7qFLkvFXMcJdiDhZcp55WBscuyXA32JdYsrL';
        // 2
        var xprv2 = 'xprv9s21ZrQH143K3KFb122nLqnzgTLRsejV2GP84HrPWmvaPMzdMwXZ8VGTY3GAWrND2fYg9neHeYvANN58XjiJoAJ2UhxosTzBqzz4nmMchR1';
        var xpub2 = 'xpub661MyMwAqRbcFoL473ZnhyjjEVAvH7TLPVJirgG157TZGAKmuUqogHawPJUcg5KZMTKK2hpB8vMYUL9rFuLy5ZSAgndyNUde9723wRZ1Lq8';

        var shared1 = hdCrypt.genSharedKey(xprv1, xpub2, "m/0/0/1/2/3");
        var shared2 = hdCrypt.genSharedKey(xprv2, xpub1, "m/0/0/1/2/3");
        assert.equal(shared1, '74fbcc3f2e02325a0643a40f4316b0df2a1ae1cf9e49aae26b6c0ce4ba13d176');
        assert.equal(shared2, '74fbcc3f2e02325a0643a40f4316b0df2a1ae1cf9e49aae26b6c0ce4ba13d176');
        
        var text = "Hello World.  Hello World.  Hello World.  Hello World.  Hello World.  Hello World.";
        var cipher = hdCrypt.encrypt(shared1, text);
        var decryptedText = hdCrypt.decrypt(shared2, cipher);

        assert.equal(text, decryptedText);
    });

    it('should be calculate hmac using shared keys', () => {
        // 1
        var xprv1 = 'xprv9s21ZrQH143K4PKh3KrNbTu896eT6j2cE6Uaj2T3728vca21EdDitGcytYpPL8jWWA7WoKTtTzaPAoXmFqcsiWdJutsxyuc421y9dzHaN48';
        var xpub1 = 'xpub661MyMwAqRbcGsQA9MPNxbqrh8UwWBkTbKQBXQrefMfuVNM9nAXyS4wTjsRcVc6bGtrXPTP7qFLkvFXMcJdiDhZcp55WBscuyXA32JdYsrL';
        // 2
        var xprv2 = 'xprv9s21ZrQH143K3KFb122nLqnzgTLRsejV2GP84HrPWmvaPMzdMwXZ8VGTY3GAWrND2fYg9neHeYvANN58XjiJoAJ2UhxosTzBqzz4nmMchR1';
        var xpub2 = 'xpub661MyMwAqRbcFoL473ZnhyjjEVAvH7TLPVJirgG157TZGAKmuUqogHawPJUcg5KZMTKK2hpB8vMYUL9rFuLy5ZSAgndyNUde9723wRZ1Lq8';

        var shared1 = hdCrypt.genSharedKey(xprv1, xpub2, "m/0/1/1/2/3");
        var shared2 = hdCrypt.genSharedKey(xprv2, xpub1, "m/0/1/1/2/3");
        
        var text = "Hello World.  Hello World.  Hello World.  Hello World.  Hello World.  Hello World.";
        var hmac1 = hdCrypt.hmac(shared1, text);
        var hmac2 = hdCrypt.hmac(shared2, text);

        assert.equal(hmac1, hmac2);
    });
});
