import { groth16 } from "snarkjs";
import fs from "fs";
import { Wallet, SigningKey, randomBytes, hexlify, computeAddress } from "ethers";
import * as secp from "@noble/secp256k1";
import { secp256k1 } from "@noble/curves/secp256k1";
import {buildBabyjub} from "circomlibjs";

const circom_tester = require("circom_tester");
import path from "path";
const wasm_tester = circom_tester.wasm;

function snarkVerify(proof: any, publicSignals: any) {
  const vKey = JSON.parse(fs.readFileSync("./build/circuits/commitment_verification_key.json").toString());
}

function bigint_to_array(n: number, k: number, x: bigint) {
    let mod: bigint = 1n;
    for (var idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret: bigint[] = [];
    var x_temp: bigint = x;
    for (var idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}

export const getCommitment = async (pubKey: string, random: Uint8Array) => {
  const randomNum = hexlify(random)
  const randomPub = secp.getPublicKey(random, false);
  const pub0 = secp256k1.ProjectivePoint.fromHex(pubKey.substring(2))
  const pub1 = secp256k1.ProjectivePoint.fromHex(randomPub)
  const garbler = pub0.add(pub1)
  const nullifier = pub0.multiply(BigInt(randomNum));
  const garblerAddress = computeAddress("0x" + garbler.toHex())
  const nullfierAddress = computeAddress("0x" + nullifier.toHex())
  // console.log("garblerAddress", garblerAddress)
  // console.log("nullfierAddress", nullfierAddress)

  const babyJub = await buildBabyjub();
  const Fr = babyJub.F;
  const PBASE: any[] =
  [
      [Fr.e("10457101036533406547632367118273992217979173478358440826365724437999023779287"),Fr.e("19824078218392094440610104313265183977899662750282163392862422243483260492317")],
      [Fr.e("2671756056509184035029146175565761955751135805354291559563293617232983272177"),Fr.e("2663205510731142763556352975002641716101654201788071096152948830924149045094")],
      [Fr.e("5802099305472655231388284418920769829666717045250560929368476121199858275951"),Fr.e("5980429700218124965372158798884772646841287887664001482443826541541529227896")],
      [Fr.e("7107336197374528537877327281242680114152313102022415488494307685842428166594"),Fr.e("2857869773864086953506483169737724679646433914307247183624878062391496185654")],
      [Fr.e("20265828622013100949498132415626198973119240347465898028410217039057588424236"),Fr.e("1160461593266035632937973507065134938065359936056410650153315956301179689506")]
  ];
  const r = babyJub.addPoint(
    babyJub.mulPointEscalar(PBASE[0], BigInt(nullfierAddress)),
    babyJub.mulPointEscalar(PBASE[1], BigInt(garblerAddress))
  );

  return Fr.toObject(r[0])
}

const proveCommit = async () => {
  const owner = Wallet.createRandom()
  const randomArr = new Uint8Array([
    ...randomBytes(32),
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

  // // TODO
  const input = {
    senderPubKey: [
      pub_x_arr,
      pub_y_arr
    ],
    commitment: commitment,
    random: random_arr
  }

  const circuit = await wasm_tester(path.join(__dirname, "..", "circuits", "deposit.circom"));
  const witness = await circuit.calculateWitness(input)
  await circuit.checkConstraints(witness);
}

proveCommit();
