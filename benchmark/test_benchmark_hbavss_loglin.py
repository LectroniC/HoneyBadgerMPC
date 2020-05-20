from pytest import mark
from contextlib import ExitStack
from random import randint
from honeybadgermpc.polynomial import polynomials_over
from honeybadgermpc.poly_commit_log import PolyCommitLog
from honeybadgermpc.betterpairing import G1, ZR
from honeybadgermpc.hbavss import HbAvssLight, HbAvssBatch, HbAvssBatchLoglin, HbAVSSMessageType
from honeybadgermpc.field import GF
from honeybadgermpc.elliptic_curve import Subgroup
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
logger.setLevel(logging.NOTSET)


def get_avss_params(n, t):
    g, h = G1.rand(), G1.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


class CCWrappedHbAvssBatchLoglin(HbAvssBatchLoglin):
    def __init__(
            self, public_keys, private_key, crs, n, t, my_id, send, recv, pc=None, field=ZR
    ):
        self.test_sent_bytes = 0
        self.test_sent_commitments = 0
        super().__init__(public_keys, private_key, crs, n, t, my_id, send, recv, pc, field)

    def add_message_to_bytes_count(self, msg, needs_to_be_dealer=False):
        if needs_to_be_dealer:
            if self.is_dealer:
                self.test_sent_bytes += len(dumps(msg))
        else:
            self.test_sent_bytes += len(dumps(msg))

    def add_to_commitments_count(self, number_of_commitments):
        self.test_sent_commitments += number_of_commitments

    def decrypt_and_count(self):
        pass

    async def _handle_implication(
            self, avid, tag, ephemeral_public_key, commitments, j, j_sk, j_k
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
        self.add_message_to_bytes_count(implicate_msg)
        self.add_to_commitments_count(len(commitments))

        j_shared_key = pow(ephemeral_public_key, j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        try:
            mixed_batch = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
            j_shares = []
            j_witnesses = []
            for i in range(secret_count):
                temp_share, temp_witness = mixed_batch[i]
                j_shares.append(temp_share)
                j_witnesses.append(temp_witness)
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
                self.add_message_to_bytes_count(msg)

        # get phi and public key from reliable broadcast msg
        commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)
        self.add_message_to_bytes_count(dispersal_msg)
        self.add_to_commitments_count(len(commitments))

        # Same as the batch size
        secret_count = len(commitments)

        # all_encrypted_witnesses: n
        shared_key = pow(ephemeral_public_key, self.private_key)

        shares = [None] * secret_count
        witnesses = [None] * secret_count
        # Decrypt
        all_shares_valid = True
        try:
            all_wits = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
            for k in range(secret_count):
                shares[k], witnesses[k] = all_wits[k]
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key, 0))

        # call if decryption was successful
        if all_shares_valid:
            if not self.poly_commit.batch_verify_eval(
                    commitments, self.my_id + 1, shares, witnesses
            ):
                all_shares_valid = False
                # Find which share was invalid and implicate
                for k in range(secret_count):
                    if not self.poly_commit.verify_eval(
                            commitments[k],
                            self.my_id + 1,
                            shares[k],
                            witnesses[k],
                    ):  # (# noqa: E501)
                        multicast((HbAVSSMessageType.IMPLICATE, self.private_key, k))
                        break
        if all_shares_valid:
            # logger.debug("[%d] OK", self.my_id)
            # logger.info(f"OK_timestamp: {time.time()}")
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
                    int_shares = [int(shares[i]) for i in range(len(shares))]
                    self.output_queue.put_nowait(
                        (dealer_id, avss_id, int_shares, self.test_sent_bytes, self.test_sent_commitments))
                    output = True
                    # logger.debug("[%d] Output", self.my_id)
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
                        avss_msg[1],
                        avss_msg[2],
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
                self.add_message_to_bytes_count(retrieved_msg)
                self.add_to_commitments_count(len(commitments))
                try:
                    mixed_batch = SymmetricCrypto.decrypt(
                        str(avss_msg[1]).encode(), retrieved_msg
                    )
                    # logger.debug("[%d] on after decryption in kdi implication", self.my_id)
                    j_shares = []
                    j_witnesses = []
                    for i in range(secret_count):
                        temp_share, temp_witness = mixed_batch[i]
                        j_shares.append(temp_share)
                        j_witnesses.append(temp_witness)
                except Exception as e:  # TODO: Add specific exception
                    logger.warn("Implicate confirmed, bad encryption:", e)
                if (self.poly_commit.batch_verify_eval(commitments,
                                                       sender + 1, j_shares, j_witnesses)):
                    if not saved_shares[sender]:
                        saved_shared_actual_length += 1
                        saved_shares[sender] = j_shares
                # logger.debug("[%d] on finishing kdi broadcast implication", self.my_id)

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
                # logger.debug("[%d] share recovery interpolated and sent OK", self.my_id)

            # logger.debug("[%d] ready_set size is %s", self.my_id, str(ready_set))
            # logger.debug("[%d] implicate_set size is %d", self.my_id, len(implicate_set))
            # The only condition where we can terminate
            if (
                    (len(ready_set) >= 2 * self.t + 1 and output)
            ):
                # logger.debug("[%d] ok_set is %s", self.my_id, str(ok_set))
                # logger.debug("[%d] ready_set size is %s", self.my_id, str(ready_set))
                # logger.debug("[%d] exit", self.my_id)
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
        r = ZR.random()
        for k in range(secret_count):
            phi[k] = self.poly.random(self.t, values[k])
            commitments[k] = self.poly_commit.commit(phi[k], r)

        ephemeral_secret_key = self.field.random()
        ephemeral_public_key = pow(self.g, ephemeral_secret_key)
        dispersal_msg_list = [None] * n
        witnesses = self.poly_commit.double_batch_create_witness(phi, r)
        for i in range(n):
            shared_key = pow(self.public_keys[i], ephemeral_secret_key)
            z = [None] * secret_count
            for k in range(secret_count):
                z[k] = (phi[k](i + 1), witnesses[k][i])
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

        """
        logger.debug(
            "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
            self.my_id,
            avss_id,
            dealer_id,
            client_mode,
        )"""

        # In the client_mode, the dealer is the last node
        n = self.n if not client_mode else self.n + 1
        broadcast_msg = None
        dispersal_msg_list = None
        if self.my_id == dealer_id:
            self.is_dealer = True
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(values, n, self.t + 1)

        tag = f"{dealer_id}-{avss_id}-B-RBC"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        # logger.debug("[%d] Starting reliable broadcast", self.my_id)
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

        # logger.debug("[%d] After reliable broadcast", self.my_id)
        tag = f"{dealer_id}-{avss_id}-B-AVID"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        # logger.debug("[%d] Starting AVID disperse", self.my_id)
        avid = AVID(n, self.t, dealer_id, recv, send, n)

        if client_mode and self.my_id == dealer_id:
            # In client_mode, the dealer is not supposed to do
            # anything after sending the initial value.
            await avid.disperse(tag, self.my_id, dispersal_msg_list, client_mode=True)
            self.shares_future.set_result(True)
            return

        if self.my_id == dealer_id:
            self.add_message_to_bytes_count(dispersal_msg_list, True)
            self.add_message_to_bytes_count(broadcast_msg, True)

            # The length of dispersal_msg_list
            logger.debug("Dealer: [%d] (length of dispersal_msg_list)", len(dispersal_msg_list))
            commitments, ephemeral_public_key = loads(broadcast_msg)
            # The number of commitments to the polynomial
            logger.debug("Dealer: [%d] (number commitments in the broadcast)", len(commitments))

            self.add_to_commitments_count(len(commitments))
            self.add_to_commitments_count(len(dispersal_msg_list) * len(commitments))

        # start disperse in the background
        self.avid_msg_queue.put_nowait((avid, tag, dispersal_msg_list))

        # avss processing
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid)


"""
Disperse and retrieve: Disperse is counted once only on the sender(which is the dealer) side.
retrieve is counted once only on the retriever side. 

Reliable broadcast: The broadcast is counted as a sum of messages on the sender side. 
But not counted on receivers.

Send: The message is counted when sent.
"""


@mark.asyncio
@mark.parametrize(
    "t",
    [
        1,
        2,
        5,
        10,
        21,
        42,
        85
    ],
)
async def test_hbavss_loglin(test_router, t):
    n = 3 * t + 1

    g, h, pks, sks = get_avss_params(n, t)
    sends, recvs, _ = test_router(n)
    # TODO: add configurable crs specifically for poly_commit_log
    crs = [g]

    values = [ZR.random()] * (t + 1)
    avss_tasks = [None] * n
    dealer_id = randint(0, n - 1)

    shares = [None] * n
    with ExitStack() as stack:
        hbavss_list = [None] * n
        for i in range(n):
            hbavss = CCWrappedHbAvssBatchLoglin(pks, sks[i], crs, n, t, i, sends[i], recvs[i])
            hbavss_list[i] = hbavss
            stack.enter_context(hbavss)
            if i == dealer_id:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=values))
            else:
                avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
            avss_tasks[i].add_done_callback(print_exception_callback)
        outputs = await asyncio.gather(
            *[hbavss_list[i].output_queue.get() for i in range(n)]
        )
        shares = [output[2] for output in outputs]
        bytes_sent_list = [output[3] for output in outputs]
        commitments_sent_list = [output[4] for output in outputs]
        total_bytes_sent_by_deadler = 0
        total_bytes_sent_by_other_parties = 0
        for i, com in enumerate(bytes_sent_list):
            if i == dealer_id:
                total_bytes_sent_by_deadler += com
            else:
                total_bytes_sent_by_other_parties += com

        total_commitments_sent_by_deadler = 0
        total_commitments_sent_by_other_parties = 0
        for i, com in enumerate(commitments_sent_list):
            if i == dealer_id:
                total_commitments_sent_by_deadler += com
            else:
                total_commitments_sent_by_other_parties += com
        for task in avss_tasks:
            task.cancel()

    with open("hbavss_benchmark_data.txt", "a+") as result_file:
        result_file.write("Dealer bytes:" + "t=" + str(t) + ":" + str(total_bytes_sent_by_deadler * 1.0) + "\n")
        result_file.write(
            "Non Dealer bytes:" + "t=" + str(t) + ":" + str(total_bytes_sent_by_other_parties * 1.0 / (n - 1)) + "\n")
        result_file.write("Dealer commitments:" + "t=" + str(t) + ":" + str(total_commitments_sent_by_deadler) + "\n")
        result_file.write(
            "Non Dealer commitments:" + "t=" + str(t) + ":" + str(
                total_commitments_sent_by_other_parties * 1.0 / (n - 1)) + "\n")

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
        )

    assert recovered_values == values


"""
@mark.parametrize(
    "t, k",
    [
        (1, 5),
        (3, 5),
        (5, 5),
        (16, 5),
        (33, 5),
        (1, 25),
        (3, 25),
        (5, 25),
        (16, 25),
        (33, 25),
        (1, 50),
        (3, 50),
        (5, 50),
        (16, 50),
        (33, 50),
        (1, 100),
        (3, 100),
        (5, 100),
        (16, 100),
        (33, 100),
    ],
)
def test_benchmark_hbavss_dealer(test_router, benchmark, t, k):
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    field = GF(Subgroup.BLS12_381)
    g, h, pks, sks = get_avss_params(n + 1, t)
    crs = gen_pc_const_crs(t, g=g, h=h)
    pc = PolyCommitConst(crs, field=field)
    pc.preprocess_prover(8)
    pc.preprocess_verifier(8)
    values = [field.random() for _ in range(k)]
    params = (t, n, g, h, pks, sks, crs, pc, values, field)

    def _prog():
        loop.run_until_complete(hbavss_multibatch_dealer(test_router, params))

    benchmark(_prog)


@mark.parametrize(
    "t, k",
    [
        (1, 5),
        (3, 5),
        (5, 5),
        (16, 5),
        (33, 5),
        (1, 25),
        (3, 25),
        (5, 25),
        (16, 25),
        (33, 25),
        (1, 50),
        (3, 50),
        (5, 50),
        (16, 50),
        (33, 50),
        (1, 100),
        (3, 100),
        (5, 100),
        (16, 100),
        (33, 100),
    ],
)
def test_benchmark_hbavss(test_router, benchmark, t, k):
    loop = asyncio.get_event_loop()
    n = 3 * t + 1
    field = GF(Subgroup.BLS12_381)
    g, h, pks, sks = get_avss_params(n, t)
    crs = gen_pc_const_crs(t, g=g, h=h)
    pc = PolyCommitConst(crs, field=field)
    pc.preprocess_prover(8)
    pc.preprocess_verifier(8)
    values = [field.random() for _ in range(k)]
    params = (t, n, g, h, pks, sks, crs, pc, values, field)

    def _prog():
        loop.run_until_complete(hbavss_multibatch(test_router, params))

    benchmark(_prog)
"""
