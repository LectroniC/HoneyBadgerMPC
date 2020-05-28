import random
import math


class PolyCommitAMTDummy:
    def __init__(self, crs=None, degree_max=33):
        self.simulated_type = "AMT"

    # Takes a random length of bytes
    def get_random_bytes(self, length):
        return [random.getrandbits(8) for _ in range(length)]

    # One polynomial commitment for AMT is one field element is 32 bytes
    def polycommit_amt_bytes_generate(self, phi):
        amt_comm_length = 32
        return self.get_random_bytes(amt_comm_length)

    def commit(self, phi, r):
        return self.polycommit_amt_bytes_generate(phi)

    def create_witness(self, phi, r, i):
        pass

    # Create witnesses for points 1 to n. n defaults to 3*degree+1 if unset.
    def batch_create_witness(self, phi, r, n=None):
        pass

    # AMT's share is 32 bytes
    # AMT's proof is ceil(log2(n)+1) * 32
    # We are comparing under n = 3 * t + 1
    # Reference: libpolycrypto/app/BandwidthCalc.cpp
    def double_batch_create_witness_amt_bytes_generator(self, phis):
        t = len(phis[0].coeffs) - 1
        n = 3 * t + 1
        numofverifiers = n
        amt_msg_length = 32 + (math.ceil(math.log2(n)) + 1) * 32
        random_msg = [self.get_random_bytes(amt_msg_length) * len(phis)]
        return [random_msg for _ in range(numofverifiers)]

    def double_batch_create_witness(self, phis, r, n=None):
        return self.double_batch_create_witness_amt_bytes_generator(phis)

    # Always eval to true
    def verify_eval(self, c, i, phi_at_i, witness):
        return True

    # Always eval to true
    def batch_verify_eval(self, cs, i, phis_at_i, witness, degree=None):
        return True

    def preprocess_prover(self, level=8):
        pass

    def preprocess_verifier(self, level=8):
        pass


class PolyCommitLoglinDummy:
    def __init__(self, crs=None, degree_max=33):
        self.simulated_type = "Loglin"

    # Takes a random length of bytes
    def get_random_bytes(self, length):
        return [random.getrandbits(8) for _ in range(length)]

    # One polycommitment for Polycommitloglin is one field element is 32 bytes
    def polycommit_loglin_bytes_generate(self, phi):
        polycommit_loglin_comm_length = 32
        return self.get_random_bytes(polycommit_loglin_comm_length)

    def commit(self, phi, r):
        return self.polycommit_loglin_bytes_generate(phi)

    def create_witness(self, phi, r, i):
        pass

    # Create witnesses for points 1 to n. n defaults to 3*degree+1 if unset.
    def batch_create_witness(self, phi, r, n=None):
        pass

    # Polycommitloglin's share is 32 bytes
    # Polycommitloglin's proof is log2(t)*2*32 + log2(n)*log2(t)*32
    # We are comparing under n = 3 * t + 1
    def double_batch_create_witness_polycommit_loglin_bytes_generator(self, phis):
        t = len(phis[0].coeffs) - 1
        n = 3 * t + 1
        numofverifiers = n
        polycommit_loglin_msg_length = 32 + \
                                       ((math.ceil(math.log2(t)) + 1) * 2 +
                                        (math.ceil(math.log2(t)) + 1) * (math.ceil(math.log2(n)) + 1)) * 32
        random_msg = [self.get_random_bytes(polycommit_loglin_msg_length) * len(phis)]
        return [random_msg for _ in range(numofverifiers)]

    def double_batch_create_witness(self, phis, r, n=None):
        return self.double_batch_create_witness_polycommit_loglin_bytes_generator(phis)

    # Always eval to true
    def verify_eval(self, c, i, phi_at_i, witness):
        return True

    # Always eval to true
    def batch_verify_eval(self, cs, i, phis_at_i, witness, degree=None):
        return True

    def preprocess_prover(self, level=8):
        pass

    def preprocess_verifier(self, level=8):
        pass
