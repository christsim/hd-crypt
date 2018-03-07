var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var crypto = require('crypto');
var HDKey = require('hdkey');

// symmetric encryption algorithm
var algorithm = 'aes-256-ctr';

/**
 * Functions to:
 *  - generate a shared key
 *  - encrypt
 *  - decrypt
 *  - hmac
 */

/**
 * Generate a key from sender's private key and
 * the recipient's public key.
 * First derive both hd keys with the path provided
 * 
 * The reverse (my public and the recipients private)
 * will also generate the same key
 * 
 */
function genSharedKey(xprv, xpub, path) {
    //derive from path
    var derivedHDPrivateKey = HDKey.fromExtendedKey(xprv).derive(path);
    var derivedHDPublicKey = HDKey.fromExtendedKey(xpub).derive(path);

    // convert to ec key
    var privateKey = ec.keyFromPrivate(derivedHDPrivateKey.privateKey.toString('hex'), 'hex');
    var publicKey = ec.keyFromPublic(derivedHDPublicKey.publicKey.toString('hex'), 'hex');

    // derive shared key
    return privateKey.derive(publicKey.getPublic()).toString(16);
}

/**
 * Don't reuse the keys - even for different uses.
 * 
 * @param {*} key 
 * @param {*} cipherText 
 */
function hmac(key, cipherText) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(cipherText);
    return hmac.digest('hex');
}

/**
 * 
 * @param {*} key 
 * @param {*} text 
 */
function encrypt(key, text) {
    var cipher = crypto.createCipher(algorithm, key);
    var crypted = cipher.update(text, 'utf8', 'hex');
    crypted += cipher.final('hex');

    return crypted;
}

/**
 * 
 * @param {*} key 
 * @param {*} cipherText 
 */
function decrypt(key, cipherText) {
    var decipher = crypto.createDecipher(algorithm, key);
    var dec = decipher.update(cipherText, 'hex', 'utf8')
    dec += decipher.final('utf8');

    return dec;
}

module.exports = {
    encrypt,
    decrypt,
    genSharedKey,
    hmac
}
