var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var bip39 = require('bip39');
var HDKey = require('hdkey');
const BN = require('bn.js');

// symmetric encryption algorithm
var algorithm = 'aes-256-ctr';

// commit to a Value X
//  rG - public Key used as blinding factor
//   H - shared private? point on the curve
function commitTo(H, rG, x) {
    return rG.add(H.mul(x));
}

// sum two commitments using homomorphic encryption
//
function addCommitments(Cx, Cy) {
    return Cx.add(Cy);
}

// subtract two commitments
//
function subCommitments(Cx, Cy) {
    return Cx.add(Cy.neg());
}

// add two known values with blinding factors
//   and compute the committed value
//   add rX + rY (blinding factors)
//   add vX + vY (hidden values)
function addPrivately(H, rX, rY, vX, vY) {
    return ec.g.mul(rX.add(rY)).add(H.mul(vX + vY));
}

// subtract two known values with blinding factors
//   and compute the committed value
//   add rX - rY (blinding factors)
//   add vX - vY (hidden values)
function subPrivately(H, rX, rY, vX, vY) {
    // umod to wrap around if negative
    var rZ = rX.sub(rY).umod(ec.n);
    return ec.g.mul(rZ).add(H.mul(vX - vY));
}



module.exports = {
    commitTo,
    addCommitments,
    subCommitments,
    addPrivately,
    subPrivately    
}
