var assert = require('assert');

var HDCrypt = require('../src/hd-crypt.js');
var bip39 = require('bip39');
var HDKey = require('hdkey');

describe('hdCrypt', () => {
    it('can encrypt/decrypt from mnemonic', () => {
        var mnemonic = bip39.generateMnemonic();
        var xpub2 = 'xpub661MyMwAqRbcFoL473ZnhyjjEVAvH7TLPVJirgG157TZGAKmuUqogHawPJUcg5KZMTKK2hpB8vMYUL9rFuLy5ZSAgndyNUde9723wRZ1Lq8';
        var hdCrypt = HDCrypt.createFromMnemonic(mnemonic, xpub2, 'm/0/1/2/3');

        var text = 'Hello World!!!';
        var cipherData = hdCrypt.encrypt(text);
        var clearText = hdCrypt.decrypt(cipherData);

        assert.equal(text, clearText);
        assert.equal(cipherData.cryptPath, 'm/0/1/2/3/' + hdCrypt.randomPathIndex + '/0/0');
        assert.equal(cipherData.hmacPath, 'm/0/1/2/3/' + hdCrypt.randomPathIndex + '/1/0');
    });

    it('can encrypt/decrypt from xpriv', () => {
        var xpriv1 = 'xprv9s21ZrQH143K38D1mL3XTj2oMD87dmqDPSMKG9PqCWKCFYcPERzdtynK1QqYqg187VfEudGzSM5wCynhWkGLb3WLDgiziybKxKmPjz6p5Bq';
        var xpub2 = 'xpub661MyMwAqRbcFoL473ZnhyjjEVAvH7TLPVJirgG157TZGAKmuUqogHawPJUcg5KZMTKK2hpB8vMYUL9rFuLy5ZSAgndyNUde9723wRZ1Lq8';

        var hdCrypt = HDCrypt.createFromXpriv(xpriv1, xpub2, 'm/0/1/2/3');

        var text = 'Hello World!!!';
        var cipherData = hdCrypt.encrypt(text);
        var clearText = hdCrypt.decrypt(cipherData);

        assert.equal(text, clearText);
    });
    
    it('fails if hmac is incorrect', () => {
        var xpriv1 = 'xprv9s21ZrQH143K38D1mL3XTj2oMD87dmqDPSMKG9PqCWKCFYcPERzdtynK1QqYqg187VfEudGzSM5wCynhWkGLb3WLDgiziybKxKmPjz6p5Bq';
        var xpub2 = 'xpub661MyMwAqRbcFoL473ZnhyjjEVAvH7TLPVJirgG157TZGAKmuUqogHawPJUcg5KZMTKK2hpB8vMYUL9rFuLy5ZSAgndyNUde9723wRZ1Lq8';

        var hdCrypt = HDCrypt.createFromXpriv(xpriv1, xpub2, 'm/0/1/2/3');

        var text = 'Hello World!!!';
        var cipherData = hdCrypt.encrypt(text);
        cipherData.hmac += 'ab';
        assert.throws(() => hdCrypt.decrypt(cipherData), Error, "Hmac does not match");
    });

    it('can encrypt/decrypt more than one message', () => {
        // 1
        var xprv1 = 'xprv9s21ZrQH143K4PKh3KrNbTu896eT6j2cE6Uaj2T3728vca21EdDitGcytYpPL8jWWA7WoKTtTzaPAoXmFqcsiWdJutsxyuc421y9dzHaN48';
        var xpub1 = 'xpub661MyMwAqRbcGsQA9MPNxbqrh8UwWBkTbKQBXQrefMfuVNM9nAXyS4wTjsRcVc6bGtrXPTP7qFLkvFXMcJdiDhZcp55WBscuyXA32JdYsrL';
        // 2
        var xprv2 = 'xprv9s21ZrQH143K3KFb122nLqnzgTLRsejV2GP84HrPWmvaPMzdMwXZ8VGTY3GAWrND2fYg9neHeYvANN58XjiJoAJ2UhxosTzBqzz4nmMchR1';
        var xpub2 = 'xpub661MyMwAqRbcFoL473ZnhyjjEVAvH7TLPVJirgG157TZGAKmuUqogHawPJUcg5KZMTKK2hpB8vMYUL9rFuLy5ZSAgndyNUde9723wRZ1Lq8';

        var hdCrypt1 = HDCrypt.createFromXpriv(xprv1, xpub2, 'm/0/1/2/3/');
        var hdCrypt2 = HDCrypt.createFromXpriv(xprv2, xpub1, 'm/1/2/3/4');

        var text1 = "Hello world, this is a test.";
        var text2 = "Hello world, this is a test. Which is a bit longer than the previous one.";
        var text3 = text1 + text2;
        var text4 = text1 + text2 + text3;

        var cipherData1 = hdCrypt1.encrypt(text1);
        var cipherData2 = hdCrypt1.encrypt(text2);

        assert.equal(cipherData1.cryptPath, 'm/0/1/2/3/' + hdCrypt1.randomPathIndex + '/0/0');
        assert.equal(cipherData2.cryptPath, 'm/0/1/2/3/' + hdCrypt1.randomPathIndex + '/0/1');

        var clearText1 = hdCrypt2.decrypt(cipherData1);
        var clearText2 = hdCrypt2.decrypt(cipherData2);
        assert.equal(clearText1, text1);
        assert.equal(clearText2, text2);

        var cipherData3 = hdCrypt2.encrypt(text3);
        var cipherData4 = hdCrypt2.encrypt(text4);

        var clearText3 = hdCrypt1.decrypt(cipherData3);
        var clearText4 = hdCrypt1.decrypt(cipherData4);
        assert.equal(clearText3, text3);
        assert.equal(clearText4, text4);
    });

    it('README.md test', () => {

        ///Alice has her private hd key and obtains bob's public hdkey
                var xprvAlice = 'xprv9s21ZrQH143K36H62LPTgjowXf7W454FLZcMVP373Pm6L9UY1N7hHmypzQ5vMJ3JwfnwqdB7Mo997vC1mqet2ii4rpGYBnGqxwdmgTQhy8G';
                var xpubBob = 'xpub661MyMwAqRbcGn5Jk3L7nwmNWE6rywUW8aMzzFk8CsrWxfBKstpXyJNcjG5E38qRCPjP3H9vaoirMugxtTM6YvwH2xCZNWHzUaRhS4nDB8b';
        
        // She then creates the HDCrypt class using this keys, and can now encrypt a message, that only Bob
        // can read
                var hdCryptAlice = HDCrypt.createFromXpriv(xprvAlice, xpubBob);
        
                var text = 'Hello World!!!';
                var cipherData = hdCryptAlice.encrypt(text);
        
        // Bob must obtain Alice's public hd key and construct the hdCrypt class in a similar way
        // (using the mnemonic):
                var mnemonicBob = 'symptom invest course raw bottom neck view pet bag baby pen crush';
                var xpubAlice = 'xpub661MyMwAqRbcFaMZ8MvU3skg5gwzTXn6hnXxHmSibjJ5CwogYuRwqaJJqfkHJtAr94949WVmR2SZXb3Rtc6QECJQ3LkVEUmt4MWMUtigTYK';
                var hdCryptBob = HDCrypt.createFromMnemonic(mnemonicBob, xpubAlice);
        
        // Now Bob can decrypt the cipherData
                var clearText = hdCryptBob.decrypt(cipherData);
                assert.equal(clearText, 'Hello World!!!');
        
    });
            
});