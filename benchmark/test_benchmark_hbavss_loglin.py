import pypairing
from pytest import mark
from contextlib import ExitStack
from random import randint
from honeybadgermpc.betterpairing import ZR, G1
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.poly_commit_dummy import PolyCommitAMTDummy, PolyCommitLoglinDummy
from honeybadgermpc.hbavss import Hbacss0, Hbacss1, Hbacss2, HbAVSSMessageType
from honeybadgermpc.field import GF
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.utils.misc import print_exception_callback, wrap_send, subscribe_recv
import asyncio
from pickle import dumps, loads
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
import logging
import time
from honeybadgermpc.broadcast.avid import AVID
from honeybadgermpc.share_recovery import poly_lagrange_at_x, poly_interpolate_g1_at_x, interpolate_g1_at_x
import cProfile

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

mul_t_param_list = [
    (1, 4),
    (2, 4),
    (3, 4),
    (5, 4),
    (8, 4),
    (11, 4),
    (1, 10),
    (2, 10),
    (3, 10),
    (5, 10),
    (8, 10),
    (11, 10),
    (1, 33),
    (2, 33),
    (3, 33),
    (5, 33),
    (8, 33),
    (11, 33)
]


def get_avss_params(n, t):
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


def get_avss_params_pyp(n, t):
    from pypairing import G1, ZR
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


class Hbacss2_always_accept_implicates(Hbacss2):
    async def _handle_implication(
            self, avid, tag, ephemeral_public_key, orig_poly_commitments, redundant_poly_commitments, j, j_sk
    ):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = await avid.retrieve(tag, j)
        j_shared_key = pow(ephemeral_public_key, j_sk)
        secret_count = len(orig_poly_commitments)
        try:
            (j_orig_shares, j_orig_poly_witnesses,
             j_redundant_poly_witnesses) = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        j_redundant_shares = []
        # Interpolate to get redundant_shares
        for batch_idx in range(secret_count // (self.t + 1)):
            base_idx = batch_idx * (self.t + 1)
            known_coords = [[i + 1, j_orig_shares[base_idx + i]] for i in range(self.t + 1)]
            j_redundant_shares += [self.poly.interpolate_at(known_coords, i + 1) for i in
                                   range(self.t + 1, self.n)]

        FLAG_verify_correct = True
        for i in range(len(j_orig_poly_witnesses)):
            FLAG_verify_correct &= self.poly_commit.batch_verify_eval(
                orig_poly_commitments[i::(self.t + 1)], j + 1, j_orig_shares[i::(self.t + 1)], j_orig_poly_witnesses[i])
            if not FLAG_verify_correct:
                break
        if FLAG_verify_correct:
            for i in range(len(j_redundant_poly_witnesses)):
                FLAG_verify_correct &= self.poly_commit.batch_verify_eval(
                    redundant_poly_commitments[i::(self.n - (self.t + 1))], j + 1,
                    j_redundant_shares[i::(self.n - (self.t + 1))],
                    j_redundant_poly_witnesses[i]
                )
                if not FLAG_verify_correct:
                    break
        # In the dummy version always return true
        # return not FLAG_verify_correct
        return True


class Hbacss2_always_send_and_accept_implicates(Hbacss2_always_accept_implicates):
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        ok_sent = False
        implicate_sent = False
        # get phi and public key from reliable broadcast msg
        orig_poly_commitments, redundant_poly_commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        secret_count = len(orig_poly_commitments)

        # all_encrypted_witnesses: n
        shared_key = pow(ephemeral_public_key, self.private_key)

        orig_shares = []
        orig_poly_witnesses = []
        redundant_poly_witnesses = []
        all_shares_valid = True
        try:
            (orig_shares, orig_poly_witnesses,
             redundant_poly_witnesses) = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
            if not implicate_sent:
                multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
                implicate_sent = True

        redundant_shares = []
        # Interpolate to get redundant_shares
        for batch_idx in range(secret_count // (self.t + 1)):
            base_idx = batch_idx * (self.t + 1)
            known_coords = [[i + 1, orig_shares[base_idx + i]] for i in range(self.t + 1)]
            temp_interpolated_poly = self.poly.interpolate(known_coords)
            redundant_shares += [temp_interpolated_poly(i + 1) for i in
                                 range(self.t + 1, self.n)]

        total_witnesses = orig_poly_witnesses + redundant_poly_witnesses
        total_shares = []
        total_commitments = []
        for batch_idx in range(secret_count // (self.t + 1)):
            base_orig_idx = batch_idx * (self.t + 1)
            base_redundant_idx = batch_idx * (self.n - self.t - 1)
            total_shares += orig_shares[base_orig_idx:(base_orig_idx + self.t + 1)]
            total_shares += redundant_shares[base_redundant_idx:(base_redundant_idx + self.n - (self.t + 1))]
            total_commitments += orig_poly_commitments[base_orig_idx:(base_orig_idx + self.t + 1)]
            total_commitments += redundant_poly_commitments[
                                 base_redundant_idx:(base_redundant_idx + self.n - (self.t + 1))]

        # call if decryption was successful
        if all_shares_valid:
            FLAG_verify_correct = True
            for i in range(len(orig_poly_witnesses)):
                FLAG_verify_correct &= self.poly_commit.batch_verify_eval(
                    orig_poly_commitments[i::(self.t + 1)], self.my_id + 1, orig_shares[i::(self.t + 1)],
                    orig_poly_witnesses[i])
                if not FLAG_verify_correct:
                    break
            if FLAG_verify_correct:
                for i in range(len(redundant_poly_witnesses)):
                    FLAG_verify_correct &= self.poly_commit.batch_verify_eval(
                        redundant_poly_commitments[i::(self.n - (self.t + 1))], self.my_id + 1,
                        redundant_shares[i::(self.n - (self.t + 1))],
                        redundant_poly_witnesses[i]
                    )
                    if not FLAG_verify_correct:
                        break
            # Simulate the case where the party received a faulty share, thus always sending out false.
            if False and (not implicate_sent):
                logger.debug("[%d] implicate sent here %d", self.my_id, int(FLAG_verify_correct))
                multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
                implicate_sent = True
                all_shares_valid = False
        if all_shares_valid and not ok_sent:
            logger.debug("[%d] OK", self.my_id)
            logger.info(f"OK_timestamp: {time.time()}")
            multicast((HbAVSSMessageType.OK, ""))
            ok_sent = True

        logger.debug("[%d] orig_share %d", self.my_id, orig_shares[0])
        logger.debug("[%d] orig_share %d", self.my_id, orig_shares[1])
        ok_set = set()
        ready_set = set()
        implicate_set = set()

        saved_shares = [None] * self.n
        saved_shared_actual_length = 0
        output = False
        in_share_recovery = False
        ready_sent = False

        r1_sent = False
        passed_r1 = False
        passed_r2 = False

        r1_set = set()
        r2_set = set()
        r1_value_ls = []
        r2_value_ls = []

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # Line 401 on receiving IMPLICATE
            if (
                    avss_msg[0] == HbAVSSMessageType.IMPLICATE
                    and sender not in implicate_set
            ):
                implicate_set.add(sender)
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE:
                logger.debug("[%d] Received implicate from [%d]", self.my_id, sender)
                # validate the implicate
                if await self._handle_implication(
                        avid,
                        tag,
                        ephemeral_public_key,
                        orig_poly_commitments,
                        redundant_poly_commitments,
                        sender,
                        avss_msg[1]
                ):
                    # proceed to share recovery
                    in_share_recovery = True
                    logger.debug("[%d] start share recovery", self.my_id)
                logger.debug("[%d] after implication", self.my_id)
            if in_share_recovery and all_shares_valid and not r1_sent and not passed_r1:
                logger.debug("[%d] in share_recovery and all_shares_valid", self.my_id)
                for j in range(self.n):
                    msg = (HbAVSSMessageType.RECOVERY1, (total_shares[j::self.n], total_witnesses[j]))
                    send(j, msg)
                r1_sent = True
                logger.debug("[%d] after share_recovery and all_shares_valid", self.my_id)
            if in_share_recovery and avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not passed_r1:
                logger.debug("[%d] start r1", self.my_id)
                (on_receive_shares, on_receive_witnesses) = avss_msg[1]
                if self.poly_commit.batch_verify_eval(
                        total_commitments[self.my_id::self.n], sender + 1,
                        on_receive_shares,
                        on_receive_witnesses
                ):
                    r1_set.add(sender)
                    r1_value_ls.append([sender, on_receive_shares, on_receive_witnesses])
                if len(r1_set) >= (self.t + 1):
                    # Interpolate
                    interpolated_polys = []
                    for poly_idx in range(len(r1_value_ls[0][1])):
                        known_point_coords = [[r1_value_ls[i][0] + 1, r1_value_ls[i][1][poly_idx]] for i in
                                              range(self.t + 1)]
                        interpolated_polys.append(self.poly.interpolate(known_point_coords))
                    # Send
                    for j in range(self.n):
                        msg = (
                            HbAVSSMessageType.RECOVERY2,
                            [interpolated_polys[i](j + 1) for i in range(len(interpolated_polys))])
                        send(j, msg)
                    passed_r1 = True
                logger.debug("[%d] after r1", self.my_id)
            if in_share_recovery and (avss_msg[
                                          0] == HbAVSSMessageType.RECOVERY2) and passed_r1 and (not ok_sent) and (
                    not passed_r2):
                logger.debug("[%d] start r2 handling", self.my_id)
                if sender not in r2_set:
                    r2_set.add(sender)
                    _, on_receive_shares = avss_msg
                    r2_value_ls.append([sender, on_receive_shares])
                if len(r2_set) >= 2 * self.t + 1:
                    # todo, replace with robust interpolate that takes at least 2t+1 values
                    # this will still interpolate the correct degree t polynomial if all points are correct
                    orig_shares = []
                    for i in range(len(r2_value_ls[0][1])):
                        coords = [[r2_value_ls[j][0] + 1, r2_value_ls[j][1][i]] for j in range(len(r2_value_ls))]
                        r2_poly = self.poly.interpolate(coords)
                        orig_shares += [r2_poly(j + 1) for j in range(self.t + 1)]
                    all_shares_valid = True
                    multicast((HbAVSSMessageType.OK, ""))
                    ok_sent = True
                    passed_r2 = True
                logger.debug("[%d] after r2 handling", self.my_id)

            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and (sender not in ok_set):
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)
                if len(ok_set) >= (2 * self.t + 1) and not ready_sent:
                    logger.debug("[%d] Sent READY", self.my_id)
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # READY
            if avss_msg[0] == HbAVSSMessageType.READY and (sender not in ready_set):
                # logger.debug("[%d] Received READY from [%d]", self.my_id, sender)
                ready_set.add(sender)
                if len(ready_set) >= (self.t + 1) and not ready_sent:
                    ready_sent = True
                    logger.debug("[%d] Sent READY", self.my_id)
                    multicast((HbAVSSMessageType.READY, ""))
            # if 2t+1 ready -> output shares
            if len(ready_set) >= (2 * self.t + 1):
                # output result by setting the future value
                if all_shares_valid and not output:
                    int_shares = [int(orig_shares[i]) for i in range(len(orig_shares))]
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)
            # The only condition where we can terminate in our test scenario where all parties have recovered
            # This line is modified from the original protocol
            if (len(ok_set) == (3 * self.t + 1)) and output:
                logger.debug("[%d] exit", self.my_id)
                break


async def hbacss2_pcl_all_correct(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss2(pks, sks[i], crs, n, t, i, sends[i], recvs[i],
                             pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbavss2_pcl_all_correct(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss2_pcl_all_correct(benchmark_router, params))

    benchmark(_prog)


async def hbacss2_pcl_one_faulty_share(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_i = randint(1, n - 1)
    # fault_i = 4
    fault_k = randint(1, len(values) - 1)
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = None
            if i != fault_i:
                hbavss = Hbacss2_always_accept_implicates(pks, sks[i], crs, n, t, i, sends[i], recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss2_always_send_and_accept_implicates(pks, sks[i], crs, n, t, i, sends[i],
                                                                   recvs[i], pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbavss2_pcl_one_faulty_share(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss2_pcl_one_faulty_share(benchmark_router, params))

    benchmark(_prog)


async def hbacss2_pcl_max_faulty_shares(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_is = [randint(1, n - 1) for _ in range(t)]
    # fault_i = 4
    fault_k = randint(1, len(values) - 1)
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = None
            if i not in fault_is:
                hbavss = Hbacss2_always_accept_implicates(pks, sks[i], crs, n, t, i, sends[i], recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss2_always_send_and_accept_implicates(pks, sks[i], crs, n, t, i, sends[i],
                                                                   recvs[i], pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss2_pcl_max_faulty_shares(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss2_pcl_max_faulty_shares(benchmark_router, params))

    benchmark(_prog)


class Hbacss1_always_accept_implicates(Hbacss1):
    async def _handle_implication(
            self, avid, tag, ephemeral_public_key, commitments, j, j_sk
    ):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = await avid.retrieve(tag, j)
        j_shared_key = pow(ephemeral_public_key, j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
            # j_shares = []
            # j_witnesses = []
            # for i in range(secret_count):
            #    temp_share, temp_witness = mixed_batch[i]
            #    j_shares.append(temp_share)
            #    j_witnesses.append(temp_witness)
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        self.poly_commit.batch_verify_eval(
            commitments, j + 1, j_shares, j_witnesses
        )
        return True


class Hbacss1_always_send_and_accept_implicates(
    Hbacss1_always_accept_implicates):
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        ok_sent = False
        implicate_sent = False
        # get phi and public key from reliable broadcast msg
        commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # Same as the batch size
        secret_count = len(commitments)

        # all_encrypted_witnesses: n
        shared_key = pow(ephemeral_public_key, self.private_key)

        shares = [None] * secret_count
        witnesses = [None] * secret_count
        # Decrypt
        all_shares_valid = True
        try:
            # all_wits = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
            # for k in range(secret_count):
            #    shares[k], witnesses[k] = all_wits[k]
            shares, witnesses = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
            if not implicate_sent:
                multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
                implicate_sent = True

        # Insert random shares for benchmarking
        # witnesses = [pypairing.G1.rand() for _ in range(secret_count)]

        # call if decryption was successful
        if all_shares_valid:
            self.poly_commit.batch_verify_eval(
                commitments, self.my_id + 1, shares, witnesses
            )
            # Modified so it would always send implicate.
            if True:
                if not implicate_sent:
                    multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
                    implicate_sent = True
                all_shares_valid = False
        if all_shares_valid and not ok_sent:
            logger.debug("[%d] OK", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
            ok_sent = True
        ok_set = set()
        ready_set = set()
        implicate_set = set()
        saved_shares = [None] * self.n
        saved_shared_actual_length = 0
        output = False
        in_share_recovery = False
        ready_sent = False

        sent_r1 = False
        sent_r2 = False

        r1_set = set()
        r2_set = set()
        r1_coords = []
        r2_coords = []

        # assume we've already reached share recovery and there are a total of t+1 secrets
        known_commits = commitments
        known_commit_coords = [[i + 1, known_commits[i]] for i in range(self.t + 1)]
        # line 502
        interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in
                                range(self.t + 1, self.n)]
        all_commits = known_commits + interpolated_commits
        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("[%d] Received implicate from [%d]", self.my_id, sender)
                    # validate the implicate
                    if await self._handle_implication(
                            avid,
                            tag,
                            ephemeral_public_key,
                            commitments,
                            sender,
                            avss_msg[1]
                    ):
                        # proceed to share recovery
                        in_share_recovery = True
                    logger.debug("[%d] after implicate from [%d] %d", self.my_id, sender, int(in_share_recovery))

            if in_share_recovery and all_shares_valid and not sent_r1:
                logger.debug("[%d] prev sent r1", self.my_id)

                # the proofs for the specific shares held by this node
                known_evalproofs = witnesses
                known_evalproof_coords = [[i + 1, known_evalproofs[i]] for i in range(self.t + 1)]

                # line 504
                interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
                                           range(self.t + 1, self.n)]
                all_evalproofs = known_evalproofs + interpolated_evalproofs

                # another way of doing the bivariate polynomial. Essentially the same as how commits are interpolated
                known_points = shares
                known_point_coords = [[i + 1, known_points[i]] for i in range(self.t + 1)]
                # would probably be faster to interpolate the full polynomial and evaluate it at the rest of the points
                interpolated_points = [self.poly.interpolate_at(known_point_coords, i + 1) for i in
                                       range(self.t + 1, self.n)]
                all_points = known_points + interpolated_points
                # lines 505-506
                for j in range(self.n):
                    send(j, (HbAVSSMessageType.RECOVERY1, all_points[j], all_evalproofs[j]))
                sent_r1 = True
                logger.debug("[%d] sent r1", self.my_id)

            if in_share_recovery and avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not sent_r2:
                logger.debug("[%d] prev sent r2", self.my_id)
                _, point, proof = avss_msg
                if self.poly_commit.verify_eval(all_commits[self.my_id], sender + 1, point, proof):
                    if sender not in r1_set:
                        r1_set.add(sender)
                        r1_coords.append([sender, point])
                    if len(r1_set) == self.t + 1:
                        r1_poly = self.poly.interpolate(r1_coords)
                        # line
                        for j in range(self.n):
                            send(j, (HbAVSSMessageType.RECOVERY2, r1_poly(j)))
                        sent_r2 = True
                        logger.debug("[%d] sent r2", self.my_id)

            if in_share_recovery and avss_msg[0] == HbAVSSMessageType.RECOVERY2 and sent_r2:
                if sender not in r2_set:
                    r2_set.add(sender)
                    _, point = avss_msg
                r2_coords.append([sender, point])
                if len(r2_set) == 2 * self.t + 1:
                    # todo, replace with robust interpolate that takes at least 2t+1 values
                    # this will still interpolate the correct degree t polynomial if all points are correct
                    r2_poly = self.poly.interpolate(r2_coords)
                    outshares = [r2_poly(i) for i in range(self.t + 1)]
                    multicast((HbAVSSMessageType.OK, ""))
                    ok_sent = True
                    all_shares_valid = True

            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                ok_set.add(sender)
                if len(ok_set) >= (2 * self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # READY
            if avss_msg[0] == HbAVSSMessageType.READY and (sender not in ready_set):
                # logger.debug("[%d] Received READY from [%d]", self.my_id, sender)
                ready_set.add(sender)
                if len(ready_set) >= (self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # if 2t+1 ready -> output shares
            if len(ready_set) >= (2 * self.t + 1):
                # output result by setting the future value
                if all_shares_valid and not output:
                    int_shares = [int(shares[i]) for i in range(len(shares))]
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            # Modified so it can terminate.
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break


async def hbacss1_pcl_all_correct(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss1(pks, sks[i], crs, n, t, i,
                             sends[i],
                             recvs[i], pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss1_pcl_all_correct(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss1_pcl_all_correct(benchmark_router, params))

    benchmark(_prog)


async def hbacss1_pcl_one_faulty_share(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_i = randint(1, n - 1)
    # fault_i = 4
    # fault_k = randint(1, len(values) - 1)
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = None
            if i != fault_i:
                hbavss = Hbacss1_always_accept_implicates(pks, sks[i], crs, n, t, i, sends[i],
                                                          recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss1_always_send_and_accept_implicates(pks, sks[i], crs, n, t, i,
                                                                   sends[i],
                                                                   recvs[i], pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss1_pcl_one_faulty_share(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss1_pcl_one_faulty_share(benchmark_router, params))

    benchmark(_prog)


async def hbacss1_pcl_max_faulty_shares(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_is = [randint(1, n - 1) for _ in range(t)]
    # fault_k = randint(1, len(values) - 1)
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = None
            if i not in fault_is:
                hbavss = Hbacss1_always_accept_implicates(pks, sks[i], crs, n, t, i,
                                                          sends[i],
                                                          recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss1_always_send_and_accept_implicates(pks, sks[i], crs, n, t,
                                                                   i,
                                                                   sends[i],
                                                                   recvs[i], pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss1_pcl_max_faulty_shares(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss1_pcl_max_faulty_shares(benchmark_router, params))

    benchmark(_prog)


class Hbacss0_always_accept_implicates(Hbacss0):
    async def _handle_implication(
            self, avid, tag, ephemeral_public_key, commitments, j, j_sk
    ):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = await avid.retrieve(tag, j)
        j_shared_key = pow(ephemeral_public_key, j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
            # j_shares = []
            # j_witnesses = []
            # for i in range(secret_count):
            #    temp_share, temp_witness = mixed_batch[i]
            #    j_shares.append(temp_share)
            #    j_witnesses.append(temp_witness)
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        self.poly_commit.batch_verify_eval(
            commitments, j + 1, j_shares, j_witnesses
        )
        return True


class Hbacss0_always_send_and_accept_implicates(Hbacss0):
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        ok_sent = False
        implicate_sent = False
        # get phi and public key from reliable broadcast msg
        commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # Same as the batch size
        secret_count = len(commitments)

        # all_encrypted_witnesses: n
        shared_key = pow(ephemeral_public_key, self.private_key)

        shares = [None] * secret_count
        witnesses = [None] * secret_count
        # Decrypt
        all_shares_valid = True
        try:
            shares, witnesses = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
            if not implicate_sent:
                multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
                implicate_sent = True

        # call if decryption was successful
        if all_shares_valid:
            # Modified so it would always send out implicates.
            self.poly_commit.batch_verify_eval(
                commitments, self.my_id + 1, shares, witnesses)
            if True:
                if not implicate_sent:
                    multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
                    implicate_sent = True
                all_shares_valid = False
        if all_shares_valid and not ok_sent:
            logger.debug("[%d] OK", self.my_id)
            logger.info(f"OK_timestamp: {time.time()}")
            multicast((HbAVSSMessageType.OK, ""))
            ok_sent = True

        ok_set = set()
        ready_set = set()
        implicate_set = set()
        saved_shares = [None] * self.n
        saved_shared_actual_length = 0
        output = False
        in_share_recovery = False
        ready_sent = False
        interpolated = False
        kdi_broadcast_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # logger.debug("[%d] Received implicate from [%d]", self.my_id, sender)
                    # validate the implicate
                    if await self._handle_implication(
                            avid,
                            tag,
                            ephemeral_public_key,
                            commitments,
                            sender,
                            avss_msg[1]
                    ):
                        # proceed to share recovery
                        in_share_recovery = True
                    # logger.debug("[%d] after implication", self.my_id)

            if in_share_recovery and all_shares_valid and not kdi_broadcast_sent:
                kdi = pow(ephemeral_public_key, self.private_key)
                # The third value doesn't matter
                multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
                kdi_broadcast_sent = True
                in_share_recovery = False

            if in_share_recovery and avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
                retrieved_msg = await avid.retrieve(tag, sender)
                try:
                    j_shares, j_witnesses = SymmetricCrypto.decrypt(
                        str(avss_msg[1]).encode(), retrieved_msg
                    )
                except Exception as e:  # TODO: Add specific exception
                    logger.warn("Implicate confirmed, bad encryption:", e)
                if (self.poly_commit.batch_verify_eval(commitments,
                                                       sender + 1, j_shares, j_witnesses)):
                    if not saved_shares[sender]:
                        saved_shared_actual_length += 1
                        saved_shares[sender] = j_shares

            # if t+1 in the saved_set, interpolate and sell all OK
            if in_share_recovery and saved_shared_actual_length >= self.t + 1 and not interpolated and not ok_sent:
                # Batch size
                shares = []
                for i in range(secret_count):
                    phi_coords = [
                        (j + 1, saved_shares[j][i]) for j in range(self.n) if saved_shares[j] is not None
                    ]
                    phi_i = self.poly.interpolate(phi_coords)
                    shares.append(phi_i(self.my_id + 1))
                all_shares_valid = True
                interpolated = True
                multicast((HbAVSSMessageType.OK, ""))
                ok_sent = True

            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)
                if len(ok_set) >= (2 * self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # READY
            if avss_msg[0] == HbAVSSMessageType.READY and (sender not in ready_set):
                # logger.debug("[%d] Received READY from [%d]", self.my_id, sender)
                ready_set.add(sender)
                if len(ready_set) >= (self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # if 2t+1 ready -> output shares
            if len(ready_set) >= (2 * self.t + 1):
                # output result by setting the future value
                if all_shares_valid and not output:
                    int_shares = [int(shares[i]) for i in range(len(shares))]
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            # Modified so it can terminate.
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break


async def hbacss0_pcl_all_correct(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_i = randint(1, n - 1)
    # fault_i = 4
    # fault_k = randint(1, len(values) - 1)
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = hbacss0(pks, sks[i], crs, n, t, i, sends[i],
                             recvs[i],
                             pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    mul_t_param_list,
)
def test_hbacss0_pcl_all_correct(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss0_pcl_all_correct(benchmark_router, params))

    benchmark(_prog)


async def hbacss0_pcl_one_faulty_share(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_i = randint(1, n - 1)
    # fault_i = 4
    # fault_k = randint(1, len(values) - 1)
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = None
            if i != fault_i:
                hbavss = Hbacss0_always_accept_implicates(pks, sks[i], crs, n, t, i, sends[i],
                                                          recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss0_always_send_and_accept_implicates(pks, sks[i], crs, n, t, i,
                                                                   sends[i],
                                                                   recvs[i], pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    hbacss0_pcl_all_correct,
)
def test_hbacss0_pcl_one_faulty_share(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss0_pcl_one_faulty_share(benchmark_router, params))

    benchmark(_prog)


async def hbacss0_pcl_max_faulty_shares(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    fault_is = [randint(1, n - 1) for _ in range(t)]
    # fault_k = randint(1, len(values) - 1)
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = None
            if i not in fault_is:
                hbavss = Hbacss0_always_accept_implicates(pks, sks[i], crs, n, t, i,
                                                          sends[i],
                                                          recvs[i],
                                                          pc=pcl)
            else:
                hbavss = Hbacss0_always_send_and_accept_implicates(pks, sks[i], crs, n, t,
                                                                   i,
                                                                   sends[i],
                                                                   recvs[i], pc=pcl)
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        for task in avss_tasks:
            task.cancel()


@mark.parametrize(
    "batch_multiple, t",
    hbacss0_pcl_all_correct,
)
def test_hbacss0_pcl_max_faulty_shares(benchmark_router, benchmark, batch_multiple, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * batch_multiple * (t + 1)
    crs = [g]
    params = (t, n, g, h, pks, sks, crs, values)

    def _prog():
        loop.run_until_complete(hbacss0_pcl_max_faulty_shares(benchmark_router, params))

    benchmark(_prog)
