var HDKey = require('hdkey');
var bip39 = require('bip39');
var crypto = require('crypto');
var hdCryptLib = require('./hd-crypt-lib.js');
var { pathFromInt, pathToInt } = require('./path-to-int');

// the sub paths used for encryption and hmacing
const CRYPT_PATH_ROOT = '/0/';
const HMAC_PATH_ROOT = '/1/';
const IV_PATH_ROOT = '/2/';

function createXPriv(mnemonic) {
    var hdkey = HDKey.fromMasterSeed(bip39.mnemonicToSeedHex(mnemonic));
    return hdkey.toJSON().xpriv;
}

function createFromMnemonic(mnemonic, xpub, rootPath = 'm/0/1', opts) {
    return new HDCrypt(createXPriv(mnemonic), xpub, rootPath, opts);
}

function createFromXpriv(xpriv, xpub, rootPath = 'm/0/1', opts) {
    return new HDCrypt(xpriv, xpub, rootPath, opts);
}

class HDCrypt {

    constructor(xpriv, xpub, rootPath, opts = {}) {
        this.xpriv = xpriv;
        this.xpub = xpub;
        this.rootPath = rootPath.toString().replace(/\/$/, "");    // remove trailing slash
        this.opts = opts;
        this.usedHMacPathIndices = new Set();
        this.usedCryptPathIndices = new Set();

        // get a random path for this iteration
        if(opts.useRandomPath) {
            this.randomPathIndex = "/" + crypto.randomBytes(3).readUIntBE(0, 3);
            this.rootPath += this.randomPathIndex;
        } else {
            this.randomPathIndex = ""
        }

        this.pathIndex = 0;
    }

    /**
     * 
     * @param {*} text - the clear text to encrypt
     */
    encrypt(text) {
        var timePath = "";
        if(this.opts.useTimeBase) {
            timePath = pathFromInt(Date.now())
        } 

        const pathIndex = this.pathIndex++;

        // gen key
        const cryptPath = this.rootPath + CRYPT_PATH_ROOT + pathIndex + timePath;
        const cryptSharedKey = hdCryptLib.genSharedKey(this.xpriv, this.xpub, cryptPath);

        // gen iv
        const ivPath = this.root + IV_PATH_ROOT + pathIndex + timePath;
        const iv = hdCryptLib.genSharedKey(this.xpriv, this.xpub, ivPath).substr(0, 32);

        // encrypt
        const cipherText = hdCryptLib.encrypt(cryptSharedKey, iv, text);

        const hmacPath = this.rootPath + HMAC_PATH_ROOT + pathIndex + timePath;
        const hmacSharedKey = hdCryptLib.genSharedKey(this.xpriv, this.xpub, hmacPath);
        const hmac = hdCryptLib.hmac(hmacSharedKey, cipherText, cryptPath, hmacPath); // hmac the cipher text

        return {
            cipherText,
            hmac,
            cryptPath,
            hmacPath,
            ivPath
        };
    }

    /**
     * 
     * @param {*} cipherData - the cipher text and iv to decrypt
     */
    decrypt(cipherData) {
        const { cipherText, hmac, cryptPath, hmacPath, ivPath } = cipherData;

        this.validate(hmacPath, this.rootPath + HMAC_PATH_ROOT, this.usedHMacPathIndices);
        this.validate(cryptPath, this.rootPath + CRYPT_PATH_ROOT, this.usedCryptPathIndices);

        const hmacSharedKey = hdCryptLib.genSharedKey(this.xpriv, this.xpub, hmacPath);
        const hmacNew = hdCryptLib.hmac(hmacSharedKey, cipherText, cryptPath, hmacPath); // hmac the cipher text
        if(hmacNew != hmac) {
            throw Error('Hmac does not match');
        }
        
        const cryptSharedKey = hdCryptLib.genSharedKey(this.xpriv, this.xpub, cryptPath);
        const iv = hdCryptLib.genSharedKey(this.xpriv, this.xpub, ivPath).substr(0, 32);
        const clearText = hdCryptLib.decrypt(cryptSharedKey, iv, cipherText);

        return clearText;
    }

    validate(path, rootPath, usedIndices) {
        var suffix = path.substr(rootPath.length);
        var suffixPaths = suffix.split(/\/(.+)/);
        var pathIndex = parseInt(suffixPaths[0]);

        //check if index has been used already
        if(usedIndices.has(pathIndex)) {
            throw Error("Path Index already used");
        }

        // check time
        if(this.opts.useTimeBase && !(this.opts.expiryTimeMs === 'undefined')) {
            var timeCreated = pathToInt("/" + suffixPaths[1]);
            if(Date.now() - timeCreated > this.opts.expiryTimeMs) {
                throw Error("Encrypted message expired");
            }
        }
        
        usedIndices.add(pathIndex);
    }

}

module.exports = {
    createFromMnemonic,
    createFromXpriv
}