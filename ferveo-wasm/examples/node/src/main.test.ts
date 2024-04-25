import {
  decryptWithSharedSecret,
  Dkg,
  ferveoEncrypt,
  DecryptionShareSimple,
  Keypair,
  Validator,
  AggregatedTranscript,
  combineDecryptionSharesSimple,
  ValidatorMessage,
  DecryptionSharePrecomputed,
  combineDecryptionSharesPrecomputed,
  EthereumAddress,
} from "ferveo-wasm";

const zip = <A1, A2>(a: Array<A1>, b: Array<A2>): Array<[A1, A2]> =>
  a.map((k: A1, i: number) => [k, b[i]]);

const genEthAddr = (i: number) => {
  const ethAddr =
    "0x" + "0".repeat(40 - i.toString(16).length) + i.toString(16);
  return EthereumAddress.fromString(ethAddr);
};

const TAU = 1;

function setupTest(
  sharesNum: number,
  validatorsNum: number,
  threshold: number
) {
  const validatorKeypairs: Keypair[] = [];
  const validators: Validator[] = [];
  for (let i = 0; i < validatorsNum; i++) {
    const keypair = Keypair.random();
    validatorKeypairs.push(keypair);
    const validator = new Validator(genEthAddr(i), keypair.publicKey, i);
    validators.push(validator);
  }

  // Each validator holds their own DKG instance and generates a transcript every
  // validator, including themselves
  const messages: ValidatorMessage[] = [];
  validators.forEach((sender) => {
    const dkg = new Dkg(TAU, sharesNum, threshold, validators, sender);
    const transcript = dkg.generateTranscript();
    const message = new ValidatorMessage(sender, transcript);
    messages.push(message);
  });

  // Now that every validator holds a dkg instance and a transcript for every other validator,
  // every validator can aggregate the transcripts
  const dkg = new Dkg(TAU, sharesNum, threshold, validators, validators[0]);

  // Both the server and the client can aggregate the transcripts and verify them
  const serverAggregate = dkg.aggregateTranscript(messages);
  expect(serverAggregate.verify(validatorsNum, messages)).toBe(true);
  const clientAggregate = new AggregatedTranscript(messages);
  expect(clientAggregate.verify(validatorsNum, messages)).toBe(true);

  // Client creates a ciphertext and requests decryption shares from validators
  const msg = Buffer.from("my-msg");
  const aad = Buffer.from("my-aad");
  const ciphertext = ferveoEncrypt(msg, aad, clientAggregate.publicKey);

  return {
    validatorKeypairs,
    validators,
    dkg,
    messages,
    msg,
    aad,
    ciphertext,
  };
}

// This test suite replicates tests from ferveo-wasm/tests/node.rs
describe("ferveo-wasm", () => {
  it("simple tdec variant", () => {
    const sharesNum = 4;
    const threshold = sharesNum - 1;
    [sharesNum, sharesNum + 2].forEach((validatorsNum) => {
      const {
          validatorKeypairs,
          validators,
          messages,
          msg,
          aad,
          ciphertext
      } = setupTest(sharesNum, validatorsNum, threshold);

      // Having aggregated the transcripts, the validators can now create decryption shares
      const decryptionShares: DecryptionShareSimple[] = [];
      zip(validators, validatorKeypairs).forEach(([validator, keypair]) => {
        expect(validator.publicKey.equals(keypair.publicKey)).toBe(true);

        const dkg = new Dkg(TAU, sharesNum, threshold, validators, validator);
        const serverAggregate = dkg.aggregateTranscript(messages);
        const isValid = serverAggregate.verify(validatorsNum, messages);
        expect(isValid).toBe(true);

        const decryptionShare = serverAggregate.createDecryptionShareSimple(
          dkg,
          ciphertext.header,
          aad,
          keypair
        );
        decryptionShares.push(decryptionShare);
      });

      // Now, the decryption share can be used to decrypt the ciphertext
      // This part is in the client API
      const sharedSecret = combineDecryptionSharesSimple(decryptionShares);
      const plaintext = decryptWithSharedSecret(ciphertext, aad, sharedSecret);
      expect(Buffer.from(plaintext)).toEqual(msg);
    });
  });

  it("precomputed tdec variant", () => {
    const sharesNum = 8;
    const threshold = sharesNum * 2 / 3;
    [sharesNum, sharesNum + 2].forEach((validatorsNum) => {
        const {
            validatorKeypairs,
            validators,
            messages,
            msg,
            aad,
            ciphertext
        } = setupTest(sharesNum, validatorsNum, threshold);

      // In precomputed variant, client selects a subset of validators to create decryption shares
      const selectedValidators = validators.slice(0, threshold);
      const selectedValidatorKeypairs = validatorKeypairs.slice(0, threshold);

      // Having aggregated the transcripts, the validators can now create decryption shares
      const decryptionShares: DecryptionSharePrecomputed[] = [];
      zip(selectedValidators, selectedValidatorKeypairs).forEach(([validator, keypair]) => {
        expect(validator.publicKey.equals(keypair.publicKey)).toBe(true);

        const dkg = new Dkg(TAU, sharesNum, threshold, validators, validator);
        const serverAggregate = dkg.aggregateTranscript(messages);
        const isValid = serverAggregate.verify(validatorsNum, messages);
        expect(isValid).toBe(true);

        const decryptionShare = serverAggregate.createDecryptionSharePrecomputed(
          dkg,
          ciphertext.header,
          aad,
          keypair,
          selectedValidators,
        );
        decryptionShares.push(decryptionShare);
      });

      // Now, the decryption share can be used to decrypt the ciphertext
      // This part is in the client API
      const sharedSecret = combineDecryptionSharesPrecomputed(decryptionShares);
      const plaintext = decryptWithSharedSecret(ciphertext, aad, sharedSecret);
      expect(Buffer.from(plaintext)).toEqual(msg);
    });
  });
});
