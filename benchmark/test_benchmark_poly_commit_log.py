from pytest import mark
from honeybadgermpc.betterpairing import ZR
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
import cProfile

"""
@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_commit(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phi = polynomials_over(ZR).random(t)
    benchmark(pc.commit, phi, r)


@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_create_witness(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phi = polynomials_over(ZR).random(t)
    benchmark(pc.create_witness, phi, r, 3)


@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_create_batch_witness(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phi = polynomials_over(ZR).random(t)
    pc.preprocess_prover()
    benchmark(pc.batch_create_witness, phi, r, n=3 * t + 1)

@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_double_create_batch_witness_10_polys(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phis = []
    for _ in range(10):
        phis.append(polynomials_over(ZR).random(t))
    pc.preprocess_prover()
    benchmark(pc.double_batch_create_witness, phis, r, n=(3 * t + 1)*len(phis))



@mark.parametrize("t", [10,20,30,40,50])
def test_benchmark_double_create_batch_witness_10_polys(benchmark, t):
    pc = PolyCommitLog(degree_max=10)
    r = ZR.random()
    phis = []
    for _ in range(t):
        phis.append(polynomials_over(ZR).random(10))
    pc.preprocess_prover()
    benchmark(pc.double_batch_create_witness, phis, r, n=(3 * 10 + 1)*len(phis))

@mark.parametrize("t", [10, 20, 30, 40, 50, 60, 70])
def test_benchmark_create_batch_witness(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phi = polynomials_over(ZR).random(t)
    pc.preprocess_prover()
    benchmark(pc.batch_create_witness, phi, r, n=3 * t + 1)

@mark.parametrize("t", [10, 20, 30, 40, 50, 60, 70])
def test_benchmark_double_create_batch_witness_10_polys(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phis = []
    for _ in range(20):
        phis.append(polynomials_over(ZR).random(t))
    pc.preprocess_prover()
    benchmark(pc.double_batch_create_witness, phis, r, n=(3 * t + 1)*len(phis))

@mark.parametrize("t", [10, 20, 30, 40, 50, 60, 70])
def test_benchmark_verify_10_polys(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phis = []
    r = ZR.random()
    cs = []
    for _ in range(t):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
        c_curr = pc.commit(phi_curr, r)
        cs.append(c_curr)
    witnesses = pc.double_batch_create_witness(phis, r)
    benchmark(pc.verify_eval, cs[0], 4, phis[0](4), witnesses[0][3])
"""


@mark.parametrize("t", [1, 2, 5, 11, 21])
def test_benchmark_batch_verify(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phis = []
    r = ZR.random()
    cs = []
    for _ in range(3*t+1):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
        c_curr = pc.commit(phi_curr, r)
        cs.append(c_curr)
    witnesses = pc.double_batch_create_witness(phis, r)

    i = 4
    phis_at_4 = []
    witnesses_p = []
    for j in range(len(phis)):
        phis_at_4.append(phis[j](i))
        witnesses_p.append(witnesses[j][i - 1])
    benchmark(pc.batch_verify_eval, cs, i, phis_at_4, witnesses_p)

@mark.parametrize("t", [0, 1, 2, 5, 11, 21])
def test_benchmark_batch_creation(benchmark, t):
    pc = PolyCommitLog(degree_max=t)
    r = ZR.random()
    phis = []
    r = ZR.random()
    cs = []
    for _ in range(3 * t + 1):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
        c_curr = pc.commit(phi_curr, r)
        cs.append(c_curr)
    benchmark(pc.double_batch_create_witness, phis, r)

if __name__ == "__main__":
    t = 33
    #t = 2
    pc = PolyCommitLog(degree_max=t)
    pc.preprocess_prover()
    phis = []
    r = ZR.random()
    cs = []
    for _ in range(3 * t + 1):
        phi_curr = polynomials_over(ZR).random(t)
        phis.append(phi_curr)
        c_curr = pc.commit(phi_curr, r)
        cs.append(c_curr)
    cProfile.run("pc.double_batch_create_witness(phis, r)")
    #witnesses = pc.double_batch_create_witness(phis, r)
    #print(len(witnesses))
    #print(len(witnesses[1]))
