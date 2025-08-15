from ferveo import (
    encrypt,
    combine_decryption_shares_simple,
    decrypt_with_shared_secret,
    Keypair,
    Validator,
    ValidatorMessage,
    Dkg,
    AggregatedTranscript,
)


def gen_eth_addr(i: int) -> str:
    return f"0x{i:040x}"  # TODO: Randomize - #207


tau = 1
security_threshold = 3
shares_num = 4
validators_num = shares_num + 2
validator_keypairs = [Keypair.random() for _ in range(0, validators_num)]
validators = [
    Validator(gen_eth_addr(i), keypair.public_key(), i)
    for i, keypair in enumerate(validator_keypairs)
]

# Validators must be sorted by their public key
validators.sort(key=lambda v: v.address)

# Each validator holds their own DKG instance and generates a transcript every
# validator, including themselves
messages = []
for sender in validators:
    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=security_threshold,
        validators=validators,
        me=sender,
    )
    messages.append(ValidatorMessage(sender, dkg.generate_transcript()))

# Now that every validator holds a dkg instance and a transcript for every other validator,
# every validator can aggregate the transcripts
me = validators[0]
dkg = Dkg(
    tau=tau,
    shares_num=shares_num,
    security_threshold=security_threshold,
    validators=validators,
    me=me,
)

# Server can aggregate the transcripts
server_aggregate = dkg.aggregate_transcripts(messages)
assert server_aggregate.verify(validators_num, messages)

# And the client can also aggregate and verify the transcripts
client_aggregate = AggregatedTranscript(messages)
assert client_aggregate.verify(validators_num, messages)

# In the meantime, the client creates a ciphertext and decryption request
msg = "abc".encode()
aad = "my-aad".encode()
ciphertext = encrypt(msg, aad, client_aggregate.public_key)

# The client can serialize/deserialize ciphertext for transport
ciphertext_ser = bytes(ciphertext)

# Let's simulate a handover
handover_slot_index = 0
incoming_validator_keypair = Keypair.random()
incoming_validator = Validator(
    gen_eth_addr(1234567), incoming_validator_keypair.public_key(), handover_slot_index
)
departing_keypair = validator_keypairs[handover_slot_index]

handover_transcript = dkg.generate_handover_transcript(
    server_aggregate,
    handover_slot_index,
    incoming_validator_keypair,
)

new_aggregate = server_aggregate.finalize_handover(
    handover_transcript, departing_keypair
)

validator_keypairs[handover_slot_index] = incoming_validator_keypair
validators[handover_slot_index] = incoming_validator

# Having aggregated the transcripts, the validators can now create decryption shares
decryption_shares = []
for validator, validator_keypair in zip(validators, validator_keypairs):
    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=security_threshold,
        validators=validators,
        me=validator,
    )
    # Create a decryption share for the ciphertext
    decryption_share = new_aggregate.create_decryption_share_simple(
        dkg, ciphertext.header, aad, validator_keypair
    )
    decryption_shares.append(decryption_share)

# We only need `threshold` decryption shares in simple variant
decryption_shares = decryption_shares[:security_threshold]

# Now, the decryption share can be used to decrypt the ciphertext
# This part is in the client API

shared_secret = combine_decryption_shares_simple(decryption_shares)

# The client should have access to the public parameters of the DKG

plaintext = decrypt_with_shared_secret(ciphertext, aad, shared_secret)
assert bytes(plaintext) == msg

print("Success!")
