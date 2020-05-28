import pypairing
from pytest import mark
from contextlib import ExitStack
from random import randint
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.poly_commit_dummy import PolyCommitAMTDummy, PolyCommitLoglinDummy
from honeybadgermpc.hbavss import HbAvssLight, HbAvssBatch, HbAvssBatchLoglin, HbAVSSMessageType
from honeybadgermpc.field import GF
from honeybadgermpc.broadcast.reliablebroadcast import reliablebroadcast
from honeybadgermpc.utils.misc import print_exception_callback, wrap_send, subscribe_recv
import asyncio
from pickle import dumps, loads
from honeybadgermpc.symmetric_crypto import SymmetricCrypto
import logging
import time
from honeybadgermpc.broadcast.avid import AVID

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)


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


class HbAvssBatchDummy:
    def __init__(
            self, public_keys, private_key, crs, n, t, my_id, send, recv, pc=None, field=pypairing.ZR
    ):
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.my_id = n, t, my_id
        self.g = crs[0]

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.field = field
        self.poly = polynomials_over(self.field)
        if pc is not None:
            self.poly_commit = pc
        else:
            self.poly_commit = None

        self.avid_msg_queue = asyncio.Queue()
        self.tasks = []
        self.shares_future = asyncio.Future()
        self.output_queue = asyncio.Queue()

    async def _recv_loop(self, q):
        while True:
            avid, tag, dispersal_msg_list = await q.get()
            self.tasks.append(
                asyncio.create_task(avid.disperse(tag, self.my_id, dispersal_msg_list))
            )

    def __enter__(self):
        self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        return self

    def __exit__(self, typ, value, traceback):
        self.subscribe_recv_task.cancel()
        self.avid_recv_task.cancel()
        for task in self.tasks:
            task.cancel()

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
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        return not self.poly_commit.batch_verify_eval(
            commitments, j + 1, j_shares, j_witnesses
        )

    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

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
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))

        # call if decryption was successful
        if all_shares_valid:
            if not self.poly_commit.batch_verify_eval(
                    commitments, self.my_id + 1, shares, witnesses
            ):
                multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
                all_shares_valid = False
        if all_shares_valid:
            logger.debug("[%d] OK", self.my_id)
            logger.info(f"OK_timestamp: {time.time()}")
            multicast((HbAVSSMessageType.OK, ""))

        ok_set = set()
        ready_set = set()
        implicate_set = set()
        saved_shares = [None] * self.n
        saved_shared_actual_length = 0
        output = False
        in_share_recovery = False
        ready_sent = False
        interpolated = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()
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
                    #int_shares = [int(shares[i]) for i in range(len(shares))]
                    #self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    self.output_queue.put_nowait((dealer_id, avss_id))
                    output = True
                    logger.debug("[%d] Output", self.my_id)
            # IMPLICATE
            if (
                    avss_msg[0] == HbAVSSMessageType.IMPLICATE
                    and sender not in implicate_set
            ):
                implicate_set.add(sender)
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE:
                # logger.debug("[%d] Received implicate from [%d]", self.my_id, sender)
                # validate the implicate
                if await self._handle_implication(
                        avid,
                        tag,
                        ephemeral_public_key,
                        commitments,
                        sender,
                        avss_msg[1]
                        # avss_msg[2],
                ):
                    # proceed to share recovery
                    in_share_recovery = True
                # logger.debug("[%d] after implication", self.my_id)

            if in_share_recovery and all_shares_valid:
                kdi = pow(ephemeral_public_key, self.private_key)
                # The third value doesn't matter
                multicast((HbAVSSMessageType.KDIBROADCAST, kdi))

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
            if in_share_recovery and saved_shared_actual_length >= self.t + 1 and not interpolated:
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
            # The only condition where we can terminate
            if (
                    (len(ready_set) >= 2 * self.t + 1 and output)
            ):
                logger.debug("[%d] exit", self.my_id)
                break

    def _get_dealer_msg(self, values, n, batch_size):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        while len(values) % (batch_size) != 0:
            values.append(0)
        secret_count = len(values)
        phi = [None] * secret_count
        commitments = [None] * secret_count
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        r = pypairing.ZR.random()
        for k in range(secret_count):
            phi[k] = self.poly.random(self.t, values[k])
            commitments[k] = self.poly_commit.commit(phi[k], r)

        ephemeral_secret_key = self.field.random()
        ephemeral_public_key = pow(self.g, ephemeral_secret_key)
        dispersal_msg_list = [None] * n
        witnesses = self.poly_commit.double_batch_create_witness(phi, r)
        for i in range(n):
            shared_key = pow(self.public_keys[i], ephemeral_secret_key)
            phis_i = [phi[k](i + 1) for k in range(batch_size)]
            z = (phis_i, witnesses[i])
            zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
            dispersal_msg_list[i] = zz

        return dumps((commitments, ephemeral_public_key)), dispersal_msg_list

    async def avss(self, avss_id, values=None, dealer_id=None, client_mode=False):
        """
        A batched version of avss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        if client_mode:
            assert dealer_id is not None
            assert dealer_id == self.n
        assert type(avss_id) is int

        logger.debug(
            "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
            self.my_id,
            avss_id,
            dealer_id,
            client_mode,
        )

        # In the client_mode, the dealer is the last node
        n = self.n if not client_mode else self.n + 1
        broadcast_msg = None
        dispersal_msg_list = None
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(values, n, self.t + 1)

        tag = f"{dealer_id}-{avss_id}-B-RBC"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        logger.debug("[%d] Starting reliable broadcast", self.my_id)
        rbc_msg = await reliablebroadcast(
            tag,
            self.my_id,
            n,
            self.t,
            dealer_id,
            broadcast_msg,
            recv,
            send,
            client_mode=client_mode,
        )  # (# noqa: E501)

        tag = f"{dealer_id}-{avss_id}-B-AVID"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        logger.debug("[%d] Starting AVID disperse", self.my_id)
        avid = AVID(n, self.t, dealer_id, recv, send, n)

        if client_mode and self.my_id == dealer_id:
            # In client_mode, the dealer is not supposed to do
            # anything after sending the initial value.
            await avid.disperse(tag, self.my_id, dispersal_msg_list, client_mode=True)
            self.shares_future.set_result(True)
            return

        # start disperse in the background
        self.avid_msg_queue.put_nowait((avid, tag, dispersal_msg_list))

        # avss processing
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid)


async def hbavssamtdummy_batch(test_router, params):
    (t, n, g, h, pks, sks, crs, values, pc) = params
    sends, recvs, _ = test_router(n)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = HbAvssBatchDummy(pks, sks[i], crs, n, t, i, sends[i], recvs[i],
                                      pc=pc)
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
    "t",
    [
        1,
        2,
        3,
        5,
        8,
        11,
        16,
        21,
        27,
        33,
        38,
        42
    ],
)
def test_hbavss_amt_end_to_end_time(test_router, benchmark, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * (t + 1)
    crs = [g]
    pc = PolyCommitAMTDummy(crs=None, degree_max=t)
    params = (t, n, g, h, pks, sks, crs, values, pc)

    def _prog():
        loop.run_until_complete(hbavssamtdummy_batch(test_router, params))

    benchmark(_prog)

@mark.parametrize(
    "t",
    [
        1,
        2,
        3,
        5,
        8,
        11,
        16,
        21,
        27,
        33,
        38,
        42
    ],
)
def test_hbavss_polycommitloglin_end_to_end_time(test_router, benchmark, t):
    from pypairing import G1, ZR
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    g, h, pks, sks = get_avss_params_pyp(n, t)
    values = [ZR.random()] * (t + 1)
    crs = [g]
    pc = PolyCommitLoglinDummy(crs=None, degree_max=t)
    params = (t, n, g, h, pks, sks, crs, values, pc)

    def _prog():
        loop.run_until_complete(hbavssamtdummy_batch(test_router, params))

    benchmark(_prog)
