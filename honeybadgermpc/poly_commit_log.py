from honeybadgermpc.betterpairing import ZR, G1
from honeybadgermpc.proofs import (
    prove_inner_product_one_known,
    verify_inner_product_one_known,
    prove_batch_inner_product_one_known,
    verify_batch_inner_product_one_known,
    prove_double_batch_inner_product_one_known,
    verify_double_batch_inner_product_one_known,
    MerkleTree,
)
import pickle


class PolyCommitLog:
    def __init__(self, crs=None, degree_max=33):
        if crs is None:
            n = degree_max + 1
            self.gs = G1.hash(b"honeybadgerg", length=n)
            self.h = G1.hash(b"honeybadgerh")
            self.u = G1.hash(b"honeybadgeru")
        else:
            assert len(crs) == 3
            [self.gs, self.h, self.u] = crs
        self.y_vecs = []

    def commit(self, phi, r):
        c = G1.one()
        for i in range(len(phi.coeffs)):
            c *= self.gs[i] ** phi.coeffs[i]
        c *= self.h ** r
        return c

    def create_witness(self, phi, r, i):
        t = len(phi.coeffs) - 1
        y_vec = [ZR(i) ** j for j in range(t + 1)]
        s_vec = [ZR.random() for _ in range(t + 1)]
        sy_prod = ZR(0)
        S = G1.one()
        for j in range(t + 1):
            S *= self.gs[j] ** s_vec[j]
            sy_prod += s_vec[j] * y_vec[j]
        T = self.gs[0] ** sy_prod
        rho = ZR.random()
        S *= self.h ** rho
        # Fiat Shamir
        challenge = ZR.hash(pickle.dumps([self.gs, self.h, self.u, S, T]))
        d_vec = [phi.coeffs[j] + s_vec[j] * challenge for j in range(t + 1)]
        D = G1.one()
        for j in range(t + 1):
            D *= self.gs[j] ** d_vec[j]
        mu = r + rho * challenge
        comm, t_hat, iproof = prove_inner_product_one_known(
            d_vec, y_vec, crs=[self.gs, self.u]
        )
        return [S, T, D, mu, t_hat, iproof]

    # Create witnesses for points 1 to n. n defaults to 3*degree+1 if unset.
    def batch_create_witness(self, phi, r, n=None):
        t = len(phi.coeffs) - 1
        if n is None:
            n = 3 * t + 1
        if len(self.y_vecs) < n:
            i = len(self.y_vecs)
            while i < n:
                self.y_vecs.append([ZR(i + 1) ** j for j in range(t + 1)])
                i += 1
        s_vec = [ZR.random() for _ in range(t + 1)]
        sy_prods = [ZR(0) for _ in range(n)]
        S = G1.one()
        T_vec = [None] * n
        witnesses = [[] for _ in range(n)]
        for i in range(t + 1):
            S *= self.gs[i] ** s_vec[i]
        for j in range(n):
            for i in range(t + 1):
                sy_prods[j] += s_vec[i] * self.y_vecs[j][i]
            T_vec[j] = self.gs[0] ** sy_prods[j]
        rho = ZR.random()
        S *= self.h ** rho
        # Fiat Shamir
        tree = MerkleTree()
        for j in range(n):
            tree.append(pickle.dumps(T_vec[j]))
        roothash = tree.get_root_hash()
        for j in range(n):
            branch = tree.get_branch(j)
            witnesses[j].append(roothash)
            witnesses[j].append(branch)
        challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
        d_vec = [phi.coeffs[j] + s_vec[j] * challenge for j in range(t + 1)]
        D = G1.one()
        for j in range(t + 1):
            D *= self.gs[j] ** d_vec[j]
        mu = r + rho * challenge
        comm, t_hats, iproofs = prove_batch_inner_product_one_known(
            d_vec, self.y_vecs, crs=[self.gs, self.u]
        )
        for j in range(len(witnesses)):
            witnesses[j] += [S, T_vec[j], D, mu, t_hats[j], iproofs[j]]
        return witnesses

    # Create witnesses for points 1 to n. n defaults to (3*degree+1) * len(phis) if unset.
    # Comparing to batch_create_witness, this takes a list of phis and reuses challenges across
    # len(phis) * len(y_vecs) number of witnesses. The returned witnesses_2d is a list of lists
    # where witnesses_2d[i][j] returns the combination of phi_i on points j.
    def double_batch_create_witness(self, phis, r, n=None):
        t = len(phis[0].coeffs) - 1
        row_length = 3 * t + 1
        if n is None:
            # There are len(phis) * (3*degree+1) vectors in total.
            n = row_length * len(phis)
        if len(self.y_vecs) < row_length:
            i = len(self.y_vecs)
            while i < row_length:
                self.y_vecs.append([ZR(i + 1) ** j for j in range(t + 1)])
                i += 1
        # length t
        s_vec = [ZR.random() for _ in range(t + 1)]
        sy_prods = [ZR(0) for _ in range(row_length)]
        S = G1.one()
        T_vec = [None] * row_length
        witnesses = [[] for _ in range(n)]
        for i in range(t + 1):
            S *= self.gs[i] ** s_vec[i]
        for j in range(row_length):
            for i in range(t + 1):
                sy_prods[j] += s_vec[i] * self.y_vecs[j][i]
            T_vec[j] = self.gs[0] ** sy_prods[j]
        rho = ZR.random()
        S *= self.h ** rho
        # Fiat Shamir
        tree = MerkleTree()
        for j in range(row_length):
            tree.append(pickle.dumps(T_vec[j]))
        roothash = tree.get_root_hash()
        for i in range(len(phis)):
            for j in range(row_length):
                branch = tree.get_branch(j)
                witnesses[i * row_length + j].append(roothash)
                witnesses[i * row_length + j].append(branch)
        challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
        d_vecs = []
        for i in range(len(phis)):
            d_vecs.append([phis[i].coeffs[j] + s_vec[j] * challenge for j in range(t + 1)])
        Ds = [G1.one() for _ in range(len(phis))]
        for i in range(len(phis)):
            for j in range(t + 1):
                Ds[i] *= self.gs[j] ** d_vecs[i][j]
        mu = r + rho * challenge
        comms, t_hats, iproofs = prove_double_batch_inner_product_one_known(
            d_vecs, self.y_vecs, crs=[self.gs, self.u]
        )
        for i in range(len(witnesses) // (row_length)):
            for j in range(row_length):
                abs_idx = i * row_length + j
                witnesses[abs_idx] += [S, T_vec[j], Ds[i], mu, t_hats[abs_idx], iproofs[i][j]]
        # Transform witnesses into a better structured 2D array.
        witnesses_2d = []
        for i in range(len(witnesses) // row_length):
            witnesses_2d.append([])
            for j in range(row_length):
                witnesses_2d[i].append(witnesses[i * row_length + j])
        return witnesses_2d

    def verify_eval(self, c, i, phi_at_i, witness):
        t = witness[-1][0] - 1
        y_vec = [ZR(i) ** j for j in range(t + 1)]
        if len(witness) == 6:
            [S, T, D, mu, t_hat, iproof] = witness
            challenge = ZR.hash(pickle.dumps([self.gs, self.h, self.u, S, T]))
        else:
            [roothash, branch, S, T, D, mu, t_hat, iproof] = witness
            if not MerkleTree.verify_membership(pickle.dumps(T), branch, roothash):
                return False
            challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
        ret = self.gs[0] ** t_hat == self.gs[0] ** phi_at_i * T ** challenge
        ret &= D * self.h ** mu == S ** challenge * c
        if len(iproof[-1]) > 3:
            ret &= verify_batch_inner_product_one_known(
                D, t_hat, y_vec, iproof, crs=[self.gs, self.u]
            )
        else:
            ret &= verify_inner_product_one_known(
                D, t_hat, y_vec, iproof, crs=[self.gs, self.u]
            )
        return ret

    # This batch_verify_eval takes a point "i" with its evaluations on multiple phis,
    # the corresponding witnesses and the commitment to those phis (cs) as inputs,
    # and returns true if all is correct.
    # Notice the witnesses need to be generated by the Merkle tree version (Which includes Merkle branches).
    def batch_verify_eval(self, cs, i, phis_at_i, witnesses):
        t = witnesses[0][-1][0] - 1
        y_vec = [ZR(i) ** j for j in range(t + 1)]
        Ds = []
        t_hats = []
        iproofs = []
        ret = True
        for j in range(len(witnesses)):
            witness = witnesses[j]
            [roothash, branch, S, T, D, mu, t_hat, iproof] = witness
            if not MerkleTree.verify_membership(pickle.dumps(T), branch, roothash):
                return False
            challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
            ret &= self.gs[0] ** t_hat == self.gs[0] ** phis_at_i[j] * T ** challenge
            ret &= D * self.h ** mu == S ** challenge * cs[j]
            Ds.append(D)
            t_hats.append(t_hat)
            iproofs.append(iproof)

        assert len(iproofs[0][-1]) > 3
        ret &= verify_double_batch_inner_product_one_known(
            Ds, t_hats, y_vec, iproofs, crs=[self.gs, self.u]
        )
        return ret

    def preprocess_prover(self, level=10):
        self.u.preprocess(level)
        # 0 to length-1
        for i in range(len(self.gs) - 1):
            self.y_vecs.append([ZR(i + 1) ** j for j in range(len(self.gs))])
