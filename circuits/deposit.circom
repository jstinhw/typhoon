pragma circom 2.1.4;

include "commitment.circom";

template Deposit() {
  signal input senderPubKey[2][4];
  signal input random[4];
  signal input commitment;

  component stealth = Stealth();
  for (var j = 0; j < 4; j++) {
    for (var i = 0; i < 2; i++) {
      stealth.senderPubKey[i][j] <== senderPubKey[i][j];
    }
    stealth.random[j] <== random[j];
  }
  
  commitment === stealth.commitment;
}

component main {public [senderPubKey, commitment]} = Deposit();