pragma circom 2.1.4;

include "merkleTree.circom";
include "commitment.circom";
include "ecdsa/zk-identity/eth.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template NotInBlacklist (levels) {
  signal input senderPubKey[2][4];
  signal input random[4];
  signal input root;
  signal input blocked;
  signal input pathElements[levels];
  signal input pathIndices[levels];
  
  // commitment is derived from pubkey
  component commitmentChecker = Commitment();
  for (var j = 0; j < 4; j++) {
    for (var i = 0; i < 2; i++) {
      commitmentChecker.senderPubKey[i][j] <== senderPubKey[i][j];
    }
    commitmentChecker.random[j] <== random[j];
  }

  // open merkle tree
  component tree = MerkleTreeChecker(levels);
  tree.leaf <== commitmentChecker.commitment;
  tree.root <== root;
  for (var i = 0; i < levels; i++) {
      tree.pathElements[i] <== pathElements[i];
      tree.pathIndices[i] <== pathIndices[i];
  }

  // address is not equal to blokced
  component pubFlatten = FlattenPubkey(64, 4);
  component pub2Addr = PubkeyToAddress();
  component iszero = IsZero();

  for (var i = 0; i < 4; i++) {
    pubFlatten.chunkedPubkey[0][i] <== senderPubKey[0][i];
    pubFlatten.chunkedPubkey[1][i] <== senderPubKey[1][i];
  }
  for (var i = 0; i < 512; i++) {
    pub2Addr.pubkeyBits[i] <== pubFlatten.pubkeyBits[i];
  }
  iszero.in <== (pub2Addr.address - blocked);
  iszero.out === 0;
}

component main {public [root, blocked]} = NotInBlacklist(20);