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
    return f"0x{i:040x}"  # TODO: Randomize - #207

def combine_shares_for_variant(v: FerveoVariant, decryption_shares):
    if v == FerveoVariant.Simple:
        return combine_decryption_shares_simple(decryption_shares)
    elif v == FerveoVariant.Precomputed:
        return combine_decryption_shares_precomputed(decryption_shares)
    else:
        raise ValueError("Unknown variant")


def scenario_for_variant(
        variant: FerveoVariant,
        shares_num,
        validators_num,
        threshold,
        dec_shares_to_use
):
    if variant not in [FerveoVariant.Simple, FerveoVariant.Precomputed]:
        raise ValueError("Unknown variant: " + variant)

    if validators_num < shares_num:
        raise ValueError("validators_num must be >= shares_num")

    if shares_num < threshold:
        raise ValueError("shares_num must be >= threshold")

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

    # We only need `shares_num` messages to aggregate the transcript
    messages = messages[:shares_num]

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

    # At this point, DKG is done, and we are proceeding to threshold decryption

    # Client creates a ciphertext and requests decryption shares from validators
    msg = "abc".encode()
    aad = "my-aad".encode()
    ciphertext = encrypt(msg, aad, client_aggregate.public_key)

    # In precomputed variant, the client selects a subset of validators to use for decryption
    if variant == FerveoVariant.Precomputed:
        selected_validators = validators[:threshold]
        selected_validator_keypairs = validator_keypairs[:threshold]
    else:
        selected_validators = validators
        selected_validator_keypairs = validator_keypairs

    # Having aggregated the transcripts, the validators can now create decryption shares
    decryption_shares = []
    for validator, validator_keypair in zip(selected_validators, selected_validator_keypairs):
        assert validator.public_key == validator_keypair.public_key()
        print("validator: ", validator.share_index)

        dkg = Dkg(
            tau=tau,
            shares_num=shares_num,
            security_threshold=threshold,
            validators=validators,
            me=validator,
        )
        server_aggregate = dkg.aggregate_transcripts(messages)
        assert server_aggregate.verify(validators_num, messages)

        if variant == FerveoVariant.Simple:
            decryption_share = server_aggregate.create_decryption_share_simple(
                dkg, ciphertext.header, aad, validator_keypair
            )
        elif variant == FerveoVariant.Precomputed:
            decryption_share = server_aggregate.create_decryption_share_precomputed(
                dkg, ciphertext.header, aad, validator_keypair, selected_validators
            )
        else:
            raise ValueError("Unknown variant")
        decryption_shares.append(decryption_share)

    # We are limiting the number of decryption shares to use for testing purposes
    decryption_shares = decryption_shares[:dec_shares_to_use]

    # Client combines the decryption shares and decrypts the ciphertext
    shared_secret = combine_shares_for_variant(variant, decryption_shares)

    if len(decryption_shares) < threshold:
        with pytest.raises(ThresholdEncryptionError):
            decrypt_with_shared_secret(ciphertext, aad, shared_secret)
        return

    plaintext = decrypt_with_shared_secret(ciphertext, aad, shared_secret)
    assert bytes(plaintext) == msg


def test_simple_tdec_has_enough_messages():
    shares_num = 8
    threshold = int(shares_num * 2 / 3)
    for validators_num in [shares_num, shares_num + 2]:
        scenario_for_variant(
            FerveoVariant.Simple,
            shares_num=shares_num,
            validators_num=validators_num,
            threshold=threshold,
            dec_shares_to_use=threshold,
        )


def test_simple_tdec_doesnt_have_enough_messages():
    shares_num = 8
    threshold = int(shares_num * 2 / 3)
    dec_shares_to_use = threshold - 1
    for validators_num in [shares_num, shares_num + 2]:
        scenario_for_variant(
            FerveoVariant.Simple,
            shares_num=shares_num,
            validators_num=validators_num,
            threshold=threshold,
            dec_shares_to_use=dec_shares_to_use,
        )


def test_precomputed_tdec_has_enough_messages():
    shares_num = 8
    threshold = int(shares_num * 2 / 3)
    dec_shares_to_use = threshold
    for validators_num in [shares_num, shares_num + 2]:
        scenario_for_variant(
            FerveoVariant.Precomputed,
            shares_num=shares_num,
            validators_num=validators_num,
            threshold=threshold,
            dec_shares_to_use=dec_shares_to_use,
        )


def test_precomputed_tdec_doesnt_have_enough_messages():
    shares_num = 8
    threshold = int(shares_num * 2 / 3)
    dec_shares_to_use = threshold - 1
    for validators_num in [shares_num, shares_num + 2]:
        scenario_for_variant(
            FerveoVariant.Simple,
            shares_num=shares_num,
            validators_num=validators_num,
            threshold=threshold,
            dec_shares_to_use=dec_shares_to_use,
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
