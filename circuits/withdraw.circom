pragma circom 2.1.4;

include "merkleTree.circom";
include "commitment.circom";
include "ecdsa/zk-identity/eth.circom";
include "ecdsa/eth_addr.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template Withdraw (levels) {
  signal input senderPubKey[2][4];
  signal input random[4];
  signal input blocked;
  signal input nullifier;
  signal input root;
  signal input recipient;
  signal input pathElements[levels];
  signal input pathIndices[levels];

  // address is not equal to blokced
  component pubFlatten = FlattenPubkey(64, 4);
  component pub2Addr = PubkeyToAddress();
  component bIszero = IsZero();

  for (var i = 0; i < 4; i++) {
    pubFlatten.chunkedPubkey[0][i] <== senderPubKey[0][i];
    pubFlatten.chunkedPubkey[1][i] <== senderPubKey[1][i];
  }
  for (var i = 0; i < 512; i++) {
    pub2Addr.pubkeyBits[i] <== pubFlatten.pubkeyBits[i];
  }
  bIszero.in <== (pub2Addr.address - blocked);
  bIszero.out === 0;

  component stealth = Stealth();
  for (var j = 0; j < 4; j++) {
    for (var i = 0; i < 2; i++) {
      stealth.senderPubKey[i][j] <== senderPubKey[i][j];
    }
    stealth.random[j] <== random[j];
  }

  // random is not equal to blocked
  component randomFlatten = FlattenPubkey(64, 4);
  component randompub2Addr = PubkeyToAddress();
  component rIszero = IsZero();

  for (var i = 0; i < 4; i++) {
    randomFlatten.chunkedPubkey[0][i] <== stealth.randomPubKey[0][i];
    randomFlatten.chunkedPubkey[1][i] <== stealth.randomPubKey[1][i];
  }
  for (var i = 0; i < 512; i++) {
    randompub2Addr.pubkeyBits[i] <== randomFlatten.pubkeyBits[i];
  }
  rIszero.in <== (randompub2Addr.address - blocked);
  rIszero.out === 0;

  // nullifier is derived from stealth
  nullifier === stealth.nullifier;

  // open merkle tree
  component tree = MerkleTreeChecker(levels);
  tree.leaf <== stealth.commitment;
  tree.root <== root;
  for (var i = 0; i < levels; i++) {
      tree.pathElements[i] <== pathElements[i];
      tree.pathIndices[i] <== pathIndices[i];
  }

  // recipient tamper protection
  signal recipientSquare;
  recipientSquare <== recipient * recipient;
}

component main {public [root, blocked, nullifier, recipient]} = Withdraw(20);
