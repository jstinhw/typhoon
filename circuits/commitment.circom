pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/pedersen_old.circom";
include "ecdsa/secp256k1.circom";
include "ecdsa/ecdsa.circom";
include "ecdsa/zk-identity/eth.circom";

// computes Pedersen(nullifier + secret)
template CommitmentHasher() {
    signal input nullifier;
    signal input garbler;
    signal output commitment;

    component commitmentHasher = Pedersen(250 * 2);
    component nullifierBits = Num2Bits(250);
    component garblerBits = Num2Bits(250);

    nullifierBits.in <== nullifier;
    garblerBits.in <== garbler;
    for (var i = 0; i < 250; i++) {
        commitmentHasher.in[i] <== nullifierBits.out[i];
        commitmentHasher.in[i + 250] <== garblerBits.out[i];
    }

    commitment <== commitmentHasher.out[0];
}

template Commitment () {
  signal input senderPubKey[2][4];
  signal input random[4];
  signal output commitment;
  
  component randomPub = ECDSAPrivToPub(64, 4);
  component nullifierGenerator = Secp256k1ScalarMult(64, 4);
  component garblerGenerator = Secp256k1AddUnequal(64, 4);
  component nullifierFlatten = FlattenPubkey(64, 4);
  component garblerFlatten = FlattenPubkey(64, 4);
  component nullifierAddr = PubkeyToAddress();
  component garblerAddr = PubkeyToAddress();
  component commitmentHasher = CommitmentHasher();

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
    }
  }

  // flatten pubkeys
  for (var i = 0; i < 4; i++) {
    nullifierFlatten.chunkedPubkey[0][i] <== nullifierGenerator.out[0][i];
    nullifierFlatten.chunkedPubkey[1][i] <== nullifierGenerator.out[1][i];
    garblerFlatten.chunkedPubkey[0][i] <== garblerGenerator.out[0][i];
    garblerFlatten.chunkedPubkey[1][i] <== garblerGenerator.out[1][i];
  }
  // compute addresses
  for (var i = 0; i < 512; i++) {
    nullifierAddr.pubkeyBits[i] <== nullifierFlatten.pubkeyBits[i];
    garblerAddr.pubkeyBits[i] <== garblerFlatten.pubkeyBits[i];
  }

  commitmentHasher.nullifier <== nullifierAddr.address;
  commitmentHasher.garbler <== garblerAddr.address;
  
  commitment <== commitmentHasher.commitment;
}
