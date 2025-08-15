from ferveo import (
    Keypair,
    Validator,
    Dkg,
)


def gen_eth_addr(i: int) -> str:
    return f"0x{i:040x}"  # TODO: Randomize - #207


tau = 1
shares_num = 4
# In precomputed variant, security threshold must be equal to shares_num
security_threshold = shares_num

validator_keypairs = [Keypair.random() for _ in range(0, shares_num)]
validators = [
    Validator(gen_eth_addr(i), keypair.public_key(), i)
    for i, keypair in enumerate(validator_keypairs)
]

# Every validator can aggregate the transcripts
dkg = Dkg(
    tau=tau,
    shares_num=shares_num,
    security_threshold=security_threshold,
    validators=[],
    me=validators[0],
)
