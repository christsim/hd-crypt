# HD Crypt

High level class that will help encrypt and decrypt data using keys
created using Hierarchical Deterministic Keys.

Usage:

Alice has her private hd key and obtains bob's public hdkey
```
        var xprvAlice = 'xprv9s21ZrQH143K36H62LPTgjowXf7W454FLZcMVP373Pm6L9UY1N7hHmypzQ5vMJ3JwfnwqdB7Mo997vC1mqet2ii4rpGYBnGqxwdmgTQhy8G';
        var xpubBob = 'xpub661MyMwAqRbcGn5Jk3L7nwmNWE6rywUW8aMzzFk8CsrWxfBKstpXyJNcjG5E38qRCPjP3H9vaoirMugxtTM6YvwH2xCZNWHzUaRhS4nDB8b';
```

She then creates the HDCrypt class using this keys, and can now encrypt a message, that only Bob
can read
```
        var hdCryptAlice = HDCrypt.createFromXpriv(xprvAlice, xpubBob);

        var text = 'Hello World!!!';
        var cipherData = hdCryptAlice.encrypt(text);
```  

Bob must obtain Alice's public hd key and construct the hdCrypt class in a similar way
(using the mnemonic):
```
        var mnemonicBob = 'symptom invest course raw bottom neck view pet bag baby pen crush';
        var xpubAlice = 'xpub661MyMwAqRbcFaMZ8MvU3skg5gwzTXn6hnXxHmSibjJ5CwogYuRwqaJJqfkHJtAr94949WVmR2SZXb3Rtc6QECJQ3LkVEUmt4MWMUtigTYK';
        var hdCryptBob = HDCrypt.createFromMnemonic(mnemonicBob, xpubAlice);
       
```

Now Bob can decrypt the cipherData
```
        var clearText = hdCryptBob.decrypt(cipherData);
        assert.equal(clearText, 'Hello World!!!');
```


## HD Crypt Lib

Library to help derive shared keys between two parties.
These keys can then be used to encrypt and decrypt data. (Used by the HDCrypt class)

Usage:

Sender's private details, not shared with anyone.  Public xpub is shared with recipient
```
        var xprv1 = 'xprv9s21ZrQH143K4PKh3KrNbTu896eT6j2cE6Uaj2T3728vca21EdDitGcytYpPL8jWWA7WoKTtTzaPAoXmFqcsiWdJutsxyuc421y9dzHaN48';
        var xpub1 = 'xpub661MyMwAqRbcGsQA9MPNxbqrh8UwWBkTbKQBXQrefMfuVNM9nAXyS4wTjsRcVc6bGtrXPTP7qFLkvFXMcJdiDhZcp55WBscuyXA32JdYsrL';
```        

Recipient's details:
```
        var xprv2 = 'xprv9s21ZrQH143K3KFb122nLqnzgTLRsejV2GP84HrPWmvaPMzdMwXZ8VGTY3GAWrND2fYg9neHeYvANN58XjiJoAJ2UhxosTzBqzz4nmMchR1';
        var xpub2 = 'xpub661MyMwAqRbcFoL473ZnhyjjEVAvH7TLPVJirgG157TZGAKmuUqogHawPJUcg5KZMTKK2hpB8vMYUL9rFuLy5ZSAgndyNUde9723wRZ1Lq8';
```

Sender generates shared key:
```
        var shared1 = hdCryptLib.genSharedKey(xprv1, xpub2, "m/0/0/1/2/3");
```

Recipient generates shared key:
```        
        var shared2 = hdCryptLib.genSharedKey(xprv2, xpub1, "m/0/0/1/2/3");
```

shared1 should equal shared2

Now the sender can encrypt
```
        var text = "Hello World";
        var cipherText = hdCryptLib.encrypt(shared1, text);
```

and the recipient can decrypt
```
        var decryptedText = hdCryptLib.decrypt(shared2, cipherText);
```
