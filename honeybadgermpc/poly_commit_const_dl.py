from pypairing import ZR, G1, G2, pair
#from honeybadgermpc.betterpairing import ZR, G1, G2, pair
from honeybadgermpc.polynomial import polynomials_over

#KZG's PolyCommitDL
class PolyCommitConstDL:
    def __init__(self, crs, field=ZR):
        assert len(crs) == 2
        (self.gs, self.ghats) = crs
        self.t = len(self.gs) - 1
        self.gg = pair(self.gs[0],(self.ghats[0]))
        self.field = field

    def commit(self, phi):
        c = G1.identity()
        i = 0
        for item in self.gs:
            c *= item ** phi.coeffs[i]
            i += 1
        # c should equal g **(phi(alpha))
        return c

    def create_witness(self, phi, i):
        poly = polynomials_over(self.field)
        div = poly([-1 * i, 1])
        psi = (phi - poly([phi(i)])) / div
        witness = G1.identity()
        j = 0
        for item in self.gs[:-1]:
            witness *= item ** psi.coeffs[j]
            j += 1
        return witness

    def verify_eval(self, c, i, phi_at_i, witness):
        lhs = pair(c, self.ghats[0])
        rhs = (
            pair(witness, (self.ghats[1] * (self.ghats[0] ** -i)))
            * self.gg ** phi_at_i
        )
        return lhs == rhs

    def preprocess_verifier(self, level=4):
        self.gg.preprocess(level)

    def preprocess_prover(self, level=4):
        for item in self.gs:
            item.preprocess(level)


def gen_pc_const_dl_crs(t, alpha=None, g=None, ghat=None):
    nonetype = type(None)
    assert type(t) is int
    assert type(alpha) in (ZR, int, nonetype)
    assert type(g) in (G1, nonetype)
    assert type(ghat) in (G2, nonetype)
    if alpha is None:
        alpha = ZR.random()
    if g is None:
        g = G1.rand()
    if ghat is None:
        ghat = G2.rand()
    (gs, ghats) = ([], [])
    for i in range(t + 1):
        gs.append(g ** (alpha ** i))
    for i in range(2):
        ghats.append(ghat ** (alpha ** i))
    crs = [gs, ghats]
    return crs

#todo make an actual test file
if __name__ == "__main__":
    #from honeybadgermpc.poly_commit_const_dl import *
    #from honeybadgermpc.polynomial import polynomials_over
    #from pypairing import ZR
    t = 3
    crs = gen_pc_const_dl_crs(t)
    poly = polynomials_over(ZR)
    s = ZR.random()
    phi = poly.random(t, s)
    pc = PolyCommitConstDL(crs)
    c = pc.commit(phi)
    w = pc.create_witness(phi, 2)
    assert pc.verify_eval(c, 2, phi(2), w)
    assert not pc.verify_eval(c, 3, phi(2), w)
    print("success!")