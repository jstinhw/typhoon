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
  signal input nullfierHash;
  signal input blocked;
  signal input root;
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

  // random is not equal to blocked
  component randomAddress = PrivKeyToAddr(64, 4);
  component rIszero = IsZero();
  for (var i = 0; i < 4; i++) {
    randomAddress.privkey[i] <== random[i];
  }
  rIszero.in <== (randomAddress.addr - blocked);
  rIszero.out === 0;

  // nullifier hash
  component stealth = Stealth();
  component nullifierBits = Num2Bits(250);
  component nullifierHasher = Pedersen(250);
  for (var j = 0; j < 4; j++) {
    for (var i = 0; i < 2; i++) {
      stealth.senderPubKey[i][j] <== senderPubKey[i][j];
    }
    stealth.random[j] <== random[j];
  }
  nullifierBits.in <== stealth.nullifier;
  for (var i = 0; i < 250; i ++) {
    nullifierHasher.in[i] <== nullifierBits.out[i];
  }
  nullfierHash === nullifierHasher.out[0];
  
  // commitment is derived from pubkey
  component commitmentChecker = CommitmentHasher();
  commitmentChecker.nullifier <== stealth.nullifier;
  commitmentChecker.garbler <== stealth.garbler;

  // open merkle tree
  component tree = MerkleTreeChecker(levels);
  tree.leaf <== commitmentChecker.commitment;
  tree.root <== root;
  for (var i = 0; i < levels; i++) {
      tree.pathElements[i] <== pathElements[i];
      tree.pathIndices[i] <== pathIndices[i];
  }
}

// component main {public [root, nullfierHash, blocked]} = Withdraw(20);
component main {public [nullfierHash, blocked]} = Withdraw(20);