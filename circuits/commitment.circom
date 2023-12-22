pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/pedersen_old.circom";
include "ecdsa/secp256k1.circom";
include "ecdsa/ecdsa.circom";
include "ecdsa/zk-identity/eth.circom";

template Stealth () {
  signal input senderPubKey[2][4];
  signal input random[4];
  signal output nullifier;
  signal output randomPubKey[2][4];
  signal output commitment;
  
  component randomPub = ECDSAPrivToPub(64, 4);
  component nullifierGenerator = Secp256k1ScalarMult(64, 4);
  component garblerGenerator = Secp256k1AddUnequal(64, 4);
  component nullifierFlatten = FlattenPubkey(64, 4);
  component garblerFlatten = FlattenPubkey(64, 4);
  component nullifierNum = Bits2Num(256);

  for (var i = 0; i < 4; i++) {
    randomPub.privkey[i] <== random[i];
  }
  for (var j = 0; j < 4; j++) {
    nullifierGenerator.scalar[j] <== random[j];
    for (var i = 0; i < 2; i++) {
      nullifierGenerator.point[i][j] <== senderPubKey[i][j];
    }
  }
  for (var i = 0; i < 2; i++) {
    for (var j = 0; j < 4; j++) {
      garblerGenerator.a[i][j] <== senderPubKey[i][j];
      garblerGenerator.b[i][j] <== randomPub.pubkey[i][j];
      randomPubKey[i][j] <== randomPub.pubkey[i][j];
    }
  }

  // flatten pubkeys
  for (var i = 0; i < 4; i++) {
    nullifierFlatten.chunkedPubkey[0][i] <== nullifierGenerator.out[0][i];
    nullifierFlatten.chunkedPubkey[1][i] <== nullifierGenerator.out[1][i];
    garblerFlatten.chunkedPubkey[0][i] <== garblerGenerator.out[0][i];
    garblerFlatten.chunkedPubkey[1][i] <== garblerGenerator.out[1][i];
  }
  for (var i = 0; i < 240; i++) {
    nullifierNum.in[i] <== nullifierFlatten.pubkeyBits[256 + i];
  }
  for (var i = 240; i < 256; i++) {
    nullifierNum.in[i] <== 0;
  }
  component commitmentHasher = Pedersen(250 * 2);
  for (var i = 0; i < 240; i++) {
    commitmentHasher.in[i] <== nullifierFlatten.pubkeyBits[256 + i];
    commitmentHasher.in[i + 250] <== garblerFlatten.pubkeyBits[256 + i];
  }
  
  for (var i = 240; i < 250; i++) {
    commitmentHasher.in[i] <== 0;
    commitmentHasher.in[i + 250] <== 0;
  }

  nullifier <== nullifierNum.out;
  commitment <== commitmentHasher.out[0];
}
