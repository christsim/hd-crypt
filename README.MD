*** HD Encrypt

Library to help derive shared keys between two parties.
These keys can then be used to encrypt data

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
        var shared1 = hdEncrypt.genSharedKey(xprv1, xpub2, "m/0/0/1/2/3");
```

Recipient generates shared key:
```        
        var shared2 = hdEncrypt.genSharedKey(xprv2, xpub1, "m/0/0/1/2/3");
```

shared1 should equal shared2

Now the sender can encrypt
```
        var text = "Hello World";
        var cipherText = hdEncrypt.encrypt(shared1, text);
```

and the recipient can decrypt
```
        var decryptedText = hdEncrypt.decrypt(shared2, cipherText);
```
