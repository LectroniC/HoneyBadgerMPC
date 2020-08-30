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
from honeybadgermpc.utils.misc import print_exception_callback, wrap_send, subscribe_recv
import asyncio
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
import logging
import time
import cProfile

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

mul_t_param_list = [
    (11, 33)
    # (1, 3),
    # (3, 3),
    # (5, 3),
    # (7, 3),
    # (9, 3),
    # (11, 3),
    # (1, 16),
    # (3, 16),
    # (5, 16),
    # (7, 16),
    # (9, 16),
    # (11, 16),
    # (1, 33),
    # (3, 33),
    # (5, 33),
    # (7, 33),
    # (9, 33),
    # (11, 33),
    # (5, 1),
    # (5, 2),
    # (5, 5),
    # (5, 10),
    # (5, 22),
    # (5, 42)
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


class Hbacss0_always_accept_implicates(Hbacss0):
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments = self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        self.poly_commit.batch_verify_eval(
            commitments, j + 1, j_shares, j_witnesses
        )
        return True

class Hbacss0_always_send_and_accept_implicates(Hbacss0_always_accept_implicates):
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self.tagvars[tag] = {}

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        # get phi and public key from reliable broadcast msg
        # commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # this function will both load information into the local variable store
        # and verify share correctness
        self.all_shares_valid = self._handle_dealer_msgs(tag, dispersal_msg, rbc_msg)

        # Modify so it would always send out implicates.
        # if self.all_shares_valid:
        if False:
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            self.all_shares_valid = False
            implicate_sent = True

        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        # todo: tag-dependent variables like this should be in tagvars
        self.in_share_recovery = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    # todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.in_share_recovery = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)
            # todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1,
                               HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
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
                if self.all_shares_valid and not output:
                    shares = self.tagvars[tag]['shares']
                    int_shares = [int(shares[i]) for i in range(len(shares))]
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

class Hbacss1_always_accept_implicates(Hbacss1):
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments = self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
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
        self.tagvars[tag] = {}

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        # get phi and public key from reliable broadcast msg
        # commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # this function will both load information into the local variable store
        # and verify share correctness
        self.all_shares_valid = self._handle_dealer_msgs(tag, dispersal_msg, rbc_msg)

        # Modify so it would always send out implicates.
        # if self.all_shares_valid:
        if False:
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            self.all_shares_valid = False
            implicate_sent = True

        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        # todo: tag-dependent variables like this should be in tagvars
        self.in_share_recovery = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    # todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.in_share_recovery = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)
            # todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1,
                               HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
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
                if self.all_shares_valid and not output:
                    shares = self.tagvars[tag]['shares']
                    int_shares = [int(shares[i]) for i in range(len(shares))]
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

class Hbacss2_always_accept_implicates(Hbacss2):
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        orig_poly_commitments = self.tagvars[tag]['orig_poly_commitments']
        redundant_poly_commitments = self.tagvars[tag]['redundant_poly_commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            return False
        # decrypt and verify
        implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)
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
        # todo:we can interpolate only if needed, but this captures the worst case for benchmarks
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
        # Modify so it would always accept implication
        # return not FLAG_verify_correct
        return True

class Hbacss2_always_send_and_accept_implicates(Hbacss2_always_accept_implicates):
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self.tagvars[tag] = {}

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        # get phi and public key from reliable broadcast msg
        # commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # this function will both load information into the local variable store
        # and verify share correctness
        self.all_shares_valid = self._handle_dealer_msgs(tag, dispersal_msg, rbc_msg)

        # Modify so it would always send out implicates.
        # if self.all_shares_valid:
        if False:
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            self.all_shares_valid = False
            implicate_sent = True

        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        # todo: tag-dependent variables like this should be in tagvars
        self.in_share_recovery = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    # todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.in_share_recovery = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)
            # todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1,
                               HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
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
                if self.all_shares_valid and not output:
                    shares = self.tagvars[tag]['shares']
                    int_shares = [int(shares[i]) for i in range(len(shares))]
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
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
def test_hbacss2_pcl_all_correct(benchmark_router, benchmark, batch_multiple, t):
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
def test_hbacss2_pcl_one_faulty_share(benchmark_router, benchmark, batch_multiple, t):
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
    fault_is = [i for i in range(t, t+t)]
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
    fault_is = [i for i in range(t, t+t)]
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

async def hbacss0_pcl_all_correct(benchmark_router, params):
    (t, n, g, h, pks, sks, crs, values) = params
    sends, recvs, _ = benchmark_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)
    pcl = PolyCommitLoglinDummy(crs=None, degree_max=t)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = Hbacss0(pks, sks[i], crs, n, t, i, sends[i],
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
    mul_t_param_list,
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
    fault_is = [i for i in range(t, t+t)]
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
    mul_t_param_list,
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
