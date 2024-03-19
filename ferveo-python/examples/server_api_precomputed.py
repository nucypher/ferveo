from ferveo import (
    encrypt,
    combine_decryption_shares_precomputed,
    decrypt_with_shared_secret,
    Keypair,
    Validator,
    ValidatorMessage,
    Dkg,
    AggregatedTranscript,
)


def gen_eth_addr(i: int) -> str:
    return f"0x{i:040x}"


tau = 1
shares_num = 4
validators_num = shares_num + 2
# In precomputed variant, security threshold must be equal to shares_num
security_threshold = shares_num

validator_keypairs = [Keypair.random() for _ in range(0, validators_num)]
validators = [
    Validator(gen_eth_addr(i), keypair.public_key(), i)
    for i, keypair in enumerate(validator_keypairs)
]

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

# Every validator can aggregate the transcripts
dkg = Dkg(
    tau=tau,
    shares_num=shares_num,
    security_threshold=security_threshold,
    validators=validators,
    me=validators[0],
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

    # We can also obtain the aggregated transcript from the side-channel (deserialize)
    aggregate = AggregatedTranscript(messages)
    assert aggregate.verify(validators_num, messages)

    # The ciphertext is obtained from the client

    # Create a decryption share for the ciphertext
    decryption_share = aggregate.create_decryption_share_precomputed(
        dkg, ciphertext.header, aad, validator_keypair
    )
    decryption_shares.append(decryption_share)

# Now, the decryption share can be used to decrypt the ciphertext
# This part is in the client API

shared_secret = combine_decryption_shares_precomputed(decryption_shares)

# The client should have access to the public parameters of the DKG

plaintext = decrypt_with_shared_secret(ciphertext, aad, shared_secret)
assert bytes(plaintext) == msg

print("Success!")
