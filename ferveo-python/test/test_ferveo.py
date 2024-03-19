import pytest

from ferveo import (
    encrypt,
    combine_decryption_shares_simple,
    combine_decryption_shares_precomputed,
    decrypt_with_shared_secret,
    AggregatedTranscript,
    Keypair,
    Validator,
    ValidatorMessage,
    Dkg,
    DkgPublicKey,
    ThresholdEncryptionError,
    FerveoVariant,
)


def gen_eth_addr(i: int) -> str:
    return f"0x{i:040x}"


def decryption_share_for_variant(v: FerveoVariant, agg_transcript):
    if v == FerveoVariant.Simple:
        return agg_transcript.create_decryption_share_simple
    elif v == FerveoVariant.Precomputed:
        return agg_transcript.create_decryption_share_precomputed
    else:
        raise ValueError("Unknown variant")


def combine_shares_for_variant(v: FerveoVariant, decryption_shares):
    if v == FerveoVariant.Simple:
        return combine_decryption_shares_simple(decryption_shares)
    elif v == FerveoVariant.Precomputed:
        return combine_decryption_shares_precomputed(decryption_shares)
    else:
        raise ValueError("Unknown variant")


def scenario_for_variant(
    variant: FerveoVariant, shares_num, validators_num, threshold, shares_to_use
):
    if variant not in [FerveoVariant.Simple, FerveoVariant.Precomputed]:
        raise ValueError("Unknown variant: " + variant)

    if validators_num < shares_num:
        raise ValueError("validators_num must be >= shares_num")

    if variant == FerveoVariant.Precomputed and shares_to_use != validators_num:
        raise ValueError(
            "In precomputed variant, shares_to_use must be equal to validators_num"
        )

    tau = 1
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
            security_threshold=threshold,
            validators=validators,
            me=sender,
        )
        messages.append(ValidatorMessage(sender, dkg.generate_transcript()))

    # Both client and server should be able to verify the aggregated transcript
    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=threshold,
        validators=validators,
        me=validators[0],
    )
    server_aggregate = dkg.aggregate_transcripts(messages)
    assert server_aggregate.verify(validators_num, messages)

    client_aggregate = AggregatedTranscript(messages)
    assert client_aggregate.verify(validators_num, messages)

    # Client creates a ciphertext and requests decryption shares from validators
    msg = "abc".encode()
    aad = "my-aad".encode()
    ciphertext = encrypt(msg, aad, client_aggregate.public_key)

    # Having aggregated the transcripts, the validators can now create decryption shares
    decryption_shares = []
    for validator, validator_keypair in zip(validators, validator_keypairs):
        assert validator.public_key == validator_keypair.public_key()
        print("validator: ", validator.share_index)

        dkg = Dkg(
            tau=tau,
            shares_num=shares_num,
            security_threshold=threshold,
            validators=validators,
            me=validator,
        )
        pvss_aggregated = dkg.aggregate_transcripts(messages)
        assert pvss_aggregated.verify(validators_num, messages)

        decryption_share = decryption_share_for_variant(variant, pvss_aggregated)(
            dkg, ciphertext.header, aad, validator_keypair
        )
        decryption_shares.append(decryption_share)

    # We are limiting the number of decryption shares to use for testing purposes
    # decryption_shares = decryption_shares[:shares_to_use]

    # Client combines the decryption shares and decrypts the ciphertext
    shared_secret = combine_shares_for_variant(variant, decryption_shares)

    if variant == FerveoVariant.Simple and len(decryption_shares) < threshold:
        with pytest.raises(ThresholdEncryptionError):
            decrypt_with_shared_secret(ciphertext, aad, shared_secret)
        return

    if variant == FerveoVariant.Precomputed and len(decryption_shares) < threshold:
        with pytest.raises(ThresholdEncryptionError):
            decrypt_with_shared_secret(ciphertext, aad, shared_secret)
        return

    plaintext = decrypt_with_shared_secret(ciphertext, aad, shared_secret)
    assert bytes(plaintext) == msg


def test_simple_tdec_has_enough_messages():
    shares_num = 4
    threshold = shares_num - 1
    for validators_num in [shares_num, shares_num + 2]:
        scenario_for_variant(
            FerveoVariant.Simple,
            shares_num=shares_num,
            validators_num=validators_num,
            threshold=threshold,
            shares_to_use=threshold,
        )


def test_simple_tdec_doesnt_have_enough_messages():
    shares_num = 4
    threshold = shares_num - 1
    for validators_num in [shares_num, shares_num + 2]:
        scenario_for_variant(
            FerveoVariant.Simple,
            shares_num=shares_num,
            validators_num=validators_num,
            threshold=threshold,
            shares_to_use=validators_num - 1,
        )


def test_precomputed_tdec_has_enough_messages():
    shares_num = 4
    threshold = shares_num  # in precomputed variant, we need all shares
    for validators_num in [shares_num, shares_num + 2]:
        scenario_for_variant(
            FerveoVariant.Precomputed,
            shares_num=shares_num,
            validators_num=validators_num,
            threshold=threshold,
            shares_to_use=validators_num,
        )


def test_precomputed_tdec_doesnt_have_enough_messages():
    shares_num = 4
    threshold = shares_num  # in precomputed variant, we need all shares
    for validators_num in [shares_num, shares_num + 2]:
        scenario_for_variant(
            FerveoVariant.Simple,
            shares_num=shares_num,
            validators_num=validators_num,
            threshold=threshold,
            shares_to_use=threshold - 1,
        )


PARAMS = [
    (1, FerveoVariant.Simple),
    (3, FerveoVariant.Simple),
    (4, FerveoVariant.Simple),
    (7, FerveoVariant.Simple),
    (8, FerveoVariant.Simple),
    (1, FerveoVariant.Precomputed),
    (3, FerveoVariant.Precomputed),
    (4, FerveoVariant.Precomputed),
    (7, FerveoVariant.Precomputed),
    (8, FerveoVariant.Precomputed),
]

TEST_CASES_WITH_THRESHOLD_RANGE = []
for shares_num, variant in PARAMS:
    for threshold in range(1, shares_num):
        TEST_CASES_WITH_THRESHOLD_RANGE.append((variant, shares_num, threshold))

# Avoid running this test case as it takes a long time
# @pytest.mark.parametrize("variant, shares_num, threshold", TEST_CASES_WITH_THRESHOLD_RANGE)
# def test_reproduce_nucypher_issue(variant, shares_num, threshold):
#     scenario_for_variant(variant, shares_num, threshold, shares_to_use=threshold)


if __name__ == "__main__":
    pytest.main(["-v", "-k", "test_ferveo"])
