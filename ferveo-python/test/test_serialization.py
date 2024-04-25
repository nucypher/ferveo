from ferveo import (
    Keypair,
    Validator,
    Dkg,
    DkgPublicKey,
    FerveoPublicKey,
    FerveoVariant,
    ValidatorMessage
)


def gen_eth_addr(i: int) -> str:
    return f"0x{i:040x}"


tau = 1
security_threshold = 3
shares_num = 4
validator_keypairs = [Keypair.random() for _ in range(shares_num)]
validators = [
    Validator(gen_eth_addr(i), keypair.public_key(), i)
    for i, keypair in enumerate(validator_keypairs)
]
validators.sort(key=lambda v: v.address)


def make_dkg_public_key():
    me = validators[0]
    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=security_threshold,
        validators=validators,
        me=me,
    )
    transcripts = [ValidatorMessage(v, dkg.generate_transcript()) for v in validators]
    aggregate = dkg.aggregate_transcripts(transcripts)
    assert aggregate.verify(shares_num, transcripts)
    return aggregate.public_key


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


def test_dkg_public_key_serialization():
    dkg_pk = make_dkg_public_key()
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
