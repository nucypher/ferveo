import pytest

from ferveo import (
    AggregatedTranscript,
    Dkg,
    DkgPublicKey,
    FerveoPublicKey,
    FerveoVariant,
    Keypair,
    Validator,
    ValidatorMessage,
)


def gen_eth_addr(i: int) -> str:
    return f"0x{i:040x}"  # TODO: Randomize - #207


tau = 1
security_threshold = 3
shares_num = 4
validator_keypairs = [Keypair.random() for _ in range(shares_num)]
validators = [
    Validator(gen_eth_addr(i), keypair.public_key(), i)
    for i, keypair in enumerate(validator_keypairs)
]
validators.sort(key=lambda v: v.address)


@pytest.fixture(scope="module")
def dkg():
    me = validators[0]
    return Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=security_threshold,
        validators=validators,
        me=me,
    )


@pytest.fixture(scope="module")
def aggregate(dkg):
    transcripts = [ValidatorMessage(v, dkg.generate_transcript()) for v in validators]
    aggregate = dkg.aggregate_transcripts(transcripts)
    assert aggregate.verify(shares_num, transcripts)
    return aggregate


def make_shared_secret():
    # TODO: Implement this
    # SharedSecret.from_bytes(os.urandom(584))
    pass


def make_pk():
    return Keypair.random().public_key()


# def test_shared_secret_serialization():
#     shared_secret = make_shared_secret()
#     serialized = bytes(shared_secret)
#     deserialized = SharedSecret.from_bytes(serialized)
#     # TODO: Implement __richcmp__
#     # assert shared_secret == deserialized
#     assert serialized == bytes(deserialized)


def test_keypair_serialization():
    keypair = Keypair.random()
    serialized = bytes(keypair)
    deserialized = Keypair.from_bytes(serialized)
    # TODO: Implement __richcmp__
    # assert serialized == deserialized
    assert serialized == bytes(deserialized)


def test_dkg_public_key_serialization(aggregate):
    dkg_pk = aggregate.public_key
    serialized = bytes(dkg_pk)
    deserialized = DkgPublicKey.from_bytes(serialized)
    # TODO: Implement __richcmp__
    assert serialized == bytes(deserialized)
    assert len(serialized) == DkgPublicKey.serialized_size()


def test_public_key_serialization():
    pk = make_pk()
    serialized = bytes(pk)
    deserialized = FerveoPublicKey.from_bytes(serialized)
    assert pk == deserialized
    assert len(serialized) == FerveoPublicKey.serialized_size()


def test_ferveo_variant_serialization():
    assert str(FerveoVariant.Precomputed) == "FerveoVariant::Precomputed"
    assert str(FerveoVariant.Simple) == "FerveoVariant::Simple"
    assert FerveoVariant.Precomputed == FerveoVariant.Precomputed
    assert FerveoVariant.Simple == FerveoVariant.Simple
    assert FerveoVariant.Precomputed != FerveoVariant.Simple


def test_aggregate_transcript_serialization(aggregate):
    serialized = bytes(aggregate)
    deserialized = AggregatedTranscript.from_bytes(serialized)
    assert bytes(aggregate.public_key) == bytes(deserialized.public_key)


@pytest.mark.parametrize("handover_slot_index", range(shares_num))
def test_handover_serialization(dkg, aggregate, handover_slot_index):
    incoming_validator_keypair = Keypair.random()
    departing_keypair = validator_keypairs[handover_slot_index]

    handover_transcript = dkg.generate_handover_transcript(
        aggregate,
        handover_slot_index,
        incoming_validator_keypair,
    )

    assert handover_transcript.share_index == handover_slot_index

    assert aggregate.validate_handover_transcript(handover_transcript)

    new_aggregate = aggregate.finalize_handover(
        handover_transcript, departing_keypair
    )

    assert bytes(new_aggregate.public_key) == bytes(aggregate.public_key)
    assert bytes(new_aggregate) != bytes(aggregate)