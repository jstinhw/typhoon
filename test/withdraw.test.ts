import {buildPedersenHash, buildBabyjub} from "circomlibjs";
import path from "path";
import { randomBytes, hexlify, SigningKey, Wallet} from "ethers";
const circom_tester = require("circom_tester");

import {bigint_to_array} from "./utils"; 
import {getProof} from "./withdraw";

describe('Withdraw', function(){
  this.timeout(1000000);
  let babyJub: any
  let pedersen;
  let F;
  let circuit: any;
  const wasm_tester = circom_tester.wasm;

  before((async () => {
    babyJub = await buildBabyjub();
      F = babyJub.F;
      pedersen = await buildPedersenHash();
      circuit = await wasm_tester(path.join(__dirname, "..", "circuits", "deposit.circom"));
  }))

  it('should withdraw', async () => {
    const owner = Wallet.createRandom()
    const blocked = await Wallet.createRandom().getAddress()
    const randomArr = new Uint8Array([
      ...randomBytes(32),
    ])

    const ucPublicKey = SigningKey.computePublicKey(
      owner.publicKey,
      false,
    )
    const pubX = '0x' + ucPublicKey.slice(4, 68)
    const pubY = '0x' + ucPublicKey.slice(68,)
    const pub_x_arr = bigint_to_array(64, 4, BigInt(pubX))
    const pub_y_arr = bigint_to_array(64, 4, BigInt(pubY))
    const random_arr = bigint_to_array(64, 4, BigInt(hexlify(randomArr))) 

    const proof = await getProof(ucPublicKey, randomArr)

    const input = {
      senderPubKey: [
        pub_x_arr,
        pub_y_arr
      ],
      random: random_arr,
      nullifier: proof.nullifier,
      blocked: BigInt(blocked),
      root: proof.root,
      recipient: owner.address,
      pathElements: proof.pathElements,
      pathIndices: proof.pathIndices,
    }
    const circuit = await wasm_tester(path.join(__dirname, "..", "circuits", "withdraw.circom"));
    const witness = await circuit.calculateWitness(input)
    await circuit.checkConstraints(witness);
  })
})