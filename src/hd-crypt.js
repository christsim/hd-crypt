var HDKey = require('hdkey');
var bip39 = require('bip39');
var crypto = require('crypto');
var hdCryptLib = require('./hd-crypt-lib.js');

const CRYPT_PATH_ROOT = '/0/';
const HMAC_PATH_ROOT = '/1/';

function createXPriv(mnemonic) {
    var hdkey = HDKey.fromMasterSeed(bip39.mnemonicToSeedHex(mnemonic));
    return hdkey.toJSON().xpriv;
}

function createFromMnemonic(mnemonic, xpub, rootPath = 'm/0/1') {
    return new HDCrypt(createXPriv(mnemonic), xpub, rootPath);
}

function createFromXpriv(xpriv, xpub, rootPath = 'm/0/1') {
    return new HDCrypt(xpriv, xpub, rootPath);
}

class HDCrypt {

    constructor(xpriv, xpub, rootPath) {
        this.xpriv = xpriv;
        this.xpub = xpub;
        this.rootPath = rootPath.toString().replace(/\/$/, "");    // remove trailing slash

        // get a radom path for this iteration
        this.randomPathIndex = crypto.randomBytes(3).readUIntBE(0, 3);
        this.rootPath += '/' + this.randomPathIndex;

        this.pathIndex = 0;
    }

    encrypt(text) {
        const pathIndex = this.pathIndex++;

        const cryptPath = this.rootPath + CRYPT_PATH_ROOT + pathIndex;
        const cryptSharedKey = hdCryptLib.genSharedKey(this.xpriv, this.xpub, cryptPath);
        const cipherText = hdCryptLib.encrypt(cryptSharedKey, text);

        const hmacPath = this.rootPath + HMAC_PATH_ROOT + pathIndex;
        const hmacSharedKey = hdCryptLib.genSharedKey(this.xpriv, this.xpub, hmacPath);
        const hmac = hdCryptLib.hmac(hmacSharedKey, cipherText, cryptPath, hmacPath); // hmac the cipher text

        return {
            cipherText,
            hmac,
            cryptPath,
            hmacPath
        };
    }

    decrypt(cipherData) {
        const { cipherText, hmac, cryptPath, hmacPath } = cipherData;

        const hmacSharedKey = hdCryptLib.genSharedKey(this.xpriv, this.xpub, hmacPath);
        const hmacNew = hdCryptLib.hmac(hmacSharedKey, cipherText, cryptPath, hmacPath); // hmac the cipher text
        if(hmacNew != hmac) {
            throw Error('Hmac does not match');
        }
        
        const cryptSharedKey = hdCryptLib.genSharedKey(this.xpriv, this.xpub, cryptPath);
        const clearText = hdCryptLib.decrypt(cryptSharedKey, cipherText);

        return clearText;
    }

}

module.exports = {
    createFromMnemonic,
    createFromXpriv
}