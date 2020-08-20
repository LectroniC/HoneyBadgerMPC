import pypairing
from honeybadgermpc.polynomial import polynomials_over
#from honeybadgermpc.betterpairing import ZR, G1
#todo change zr to pypairing.ZR


#assumes there's a total of t+1 secrets
class HbACSS1Recoverer:
    def __init__(self, crs, n, t, my_id, send, recv, shares, sharesvalid, commits, evalproofs, pc=None, field=pypairing.ZR):
        self.crs, self.n, self.t, self.my_id, self.send, self.recv, self.pc = crs, n, t, my_id, send, recv, pc
        self.poly = polynomials_over(field)
        #assume we have all the shares and proofs and know if they're valid
        self.commits = commits
        self.evalproofs = evalproofs
        self.shares = shares
        self.sharesvalid = sharesvalid

    async def _run(self):
        r1_sent = r2_sent = False
        
        #assume we've already reached share recovery and there are a total of t+1 secrets
        known_commits = self.commits
        known_commit_coords = [ [i+1, known_commits[i]] for i in range(self.t+1)]
        #line 502
        interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i+1) for i in range(self.t+1, self.n)]
        all_commits = known_commits + interpolated_commits
        
        #line 503
        if self.sharesvalid:
            #the proofs for the specific shares held by this node
            known_evalproofs = self.evalproofs
            known_evalproof_coords = [ [i+1, known_evalproofs[i]] for i in range(self.t+1)]
            #line 504
            interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i+1) for i in range(self.t+1, self.n)]
            all_evalproofs = known_evalproofs + interpolated_evalproofs
            
            #another way of doing the bivariate polynomial. Essentially the same as how commits are interpolated
            known_points = self.shares
            known_point_coords = [ [i+1, known_points[i]] for i in range(self.t+1)]
            #would probably be faster to interpolate the full polynomial and evaluate it at the rest of the points
            interpolated_points = [self.poly.interpolate_at(known_point_coords, i+1) for i in range(self.t+1, self.n)]
            all_points = known_points + interpolated_points
            #lines 505-506
            for j in range(self.n):
                self.send(j, ("R1", all_points[j], all_evalproofs[j]))
            r1_sent = True
        r1_set = set()
        r2_set = set()
        r1_coords = []
        r2_coords = []
        #receive loop
        while True:
            sender, msg = await self.recv()
            if msg[0] == "R1":
                _, point, proof = msg
                if self.pc.verify_eval(all_commits[self.my_id], sender+1, point, proof):
                    r1_set.add(sender)
                    r1_coords.append([sender, point])
                    if len(r1_set) == self.t + 1:
                        r1_poly = self.poly.interpolate(r1_coords)
                        #line 
                        for j in range(self.n):
                            self.send(j, ("R2", r1_poly(j)))
            if msg[0] == "R2":
                r2_set.add(sender)
                _, point = msg
                r2_coords.append([sender, point])
                if len(r2_set) == 2*self.t + 1:
                    #todo, replace with robust interpolate that takes at least 2t+1 values
                    #this will still interpolate the correct degree t polynomial if all points are correct
                    r2_poly = self.poly.interpolate(r2_coords)
                    outshares = [r2_poly(i) for i in range(self.t+1)]
                    assert outshares == self.shares
                    break


#Helper Functions
def lagrange_at_x(s, j, x):
    s = sorted(s)
    assert j in s
    l1 = [x - jj for jj in s if jj != j]
    l2 = [j - jj for jj in s if jj != j]
    (num, den) = (pypairing.ZR(1), pypairing.ZR(1))
    for item in l1:
        num *= item
    for item in l2:
        den *= item
    return num / den


def interpolate_g1_at_x(coords, x, order=-1):
    if order == -1:
        order = len(coords)
    xs = []
    sortedcoords = sorted(coords, key=lambda x: x[0])
    for coord in sortedcoords:
        xs.append(coord[0])
    s = set(xs[0:order])
    out = pypairing.G1.identity()
    for i in range(order):
        out *= (sortedcoords[i][1] ** (lagrange_at_x(s, xs[i], x)))
    return out

#if __name__ == "__main__":
#    from honeybadgermpc.poly_commit_const_dl import *