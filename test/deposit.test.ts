import fs from "fs";
import crypto from "crypto";
import {buildPedersenHash, buildBabyjub} from "circomlibjs";
import path from "path";
const circom_tester = require("circom_tester");
import { hexlify, SigningKey, Wallet} from "ethers";
import {bigint_to_array} from "./utils"; 
import {getCommitment} from "./deposit";

function snarkVerify(proof: any, publicSignals: any) {
  const vKey = JSON.parse(fs.readFileSync("./build/circuits/commitment_verification_key.json").toString());
}

describe('Deposit', function(){
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

    it('should create a valid commitment', async () => {
      const owner = Wallet.createRandom()
      const randomArr = new Uint8Array([
        ...crypto.randomBytes(32)
      ])

      const ucPublicKey = SigningKey.computePublicKey(
        owner.publicKey,
        false
      )
      const pubX = '0x' + ucPublicKey.slice(4, 68)
      const pubY = '0x' + ucPublicKey.slice(68,)

      const pub_x_arr = bigint_to_array(64, 4, BigInt(pubX))
      const pub_y_arr = bigint_to_array(64, 4, BigInt(pubY))
      const random_arr = bigint_to_array(64, 4, BigInt(hexlify(randomArr)))
      const commitment = await getCommitment(ucPublicKey, randomArr)
      const input = {
        senderPubKey: [
          pub_x_arr,
          pub_y_arr
        ],
        commitment: commitment,
        random: random_arr
      }
      const witness = await circuit.calculateWitness(input)
      await circuit.checkConstraints(witness);
    })

    it('should be able to create a commitment', async () => {
        // TODO
        // const { proof, publicSignals } = await groth16.fullProve({senderPubKey: 10, commitment: 21, random:10}, "build/circuits/commitment_js/commitment.wasm", "build/circuits/circuit_commitment_final.zkey");

        // snarkVerify(proof, publicSignals);
    })
})