pragma circom 2.1.4;

template NotInBlacklist () {
  signal input a;
  signal input b;
  signal output c;

  c <== a * b;
}

component main = NotInBlacklist();