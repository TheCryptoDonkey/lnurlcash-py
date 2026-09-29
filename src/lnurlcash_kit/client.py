"""Clients. Both do the same thing; only the await keyword differs.

Everything about the protocol lives in :mod:`lnurlcash_kit.protocol`, so the
sync and async paths cannot disagree about what a response means. What lives
here is the part that genuinely differs: performing the GET, and classifying
its failure by whether the request could have been processed.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx

from . import protocol
from .errors import (
    AmbiguousMint,
    AmbiguousMutation,
    NoteSpent,
    LnurlcashError,
    NoteUnknown,
    RequestRefused,
    UnverifiableNote,
    new_secrets_of,
)
from .note import with_new_k1
from .protocol import (
    DEFAULT_POLICY,
    InvoiceResult,
    MeltResult,
    MintAddressInfo,
    MutationResult,
    PayRequestInfo,
    Policy,
    Request,
    RotateResult,
    SplitResult,
    VerifyResult,
    WithdrawRequestInfo,
)
from .secrets import generate_note_secret
from .urls import is_allowed_service_url

DEFAULT_TIMEOUT = 30.0


class _Base:
    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        offline: bool = False,
        rng: Callable[[], str] = generate_note_secret,
        policy: Policy = DEFAULT_POLICY,
        mutation_retries: int = 1,
    ) -> None:
        #: Bounded wait. Without one a hung SERVICE blocks the caller forever.
        self.timeout = timeout
        #: Refuse to make any request at all. A caller holding notes offline
        #: deliberately can set this to be certain nothing reaches the
        #: network, rather than trusting that it happens not to.
        self.offline = offline
        #: Where replacement note secrets come from. Substitute for a hardware
        #: RNG or a deterministic test - and see secrets.generate_note_secret
        #: for what a caller takes on by doing so.
        self.rng = rng
        #: What this client insists a SERVICE does. The default demands a cs1
        #: on every output named by cp1 and a mintPubkey on every
        #: withdrawRequest, while tolerating an uncertified output named by a
        #: bearer h from a mint with no signer. See
        #: :class:`~lnurlcash_kit.protocol.Policy`.
        self.policy = policy
        #: How many times to re-send a rotate, split or merge whose outcome the
        #: transport lost. LUD-25 requires a SERVICE to answer a byte-identical
        #: retry with the original success ("Retrying a mutation"), so
        #: re-sending resolves the ambiguity rather than compounding it: a
        #: conforming SERVICE replays, and one that refuses leaves the caller
        #: exactly where an un-retried failure would have.
        #:
        #: Only ever applied to a request marked ``replayable``, which a melt
        #: never is. Zero gives up on the first ambiguous answer.
        self.mutation_retries = max(0, mutation_retries)

    def _guard(self, url: str) -> None:
        if self.offline:
            raise RequestRefused("Offline mode is on - no request was made.")
        if not is_allowed_service_url(url):
            raise RequestRefused(
                "Refusing to fetch that URL - only https, or http to a "
                "loopback or .onion host, is allowed."
            )

    @staticmethod
    def _decode(response: httpx.Response) -> Any:
        try:
            return json.loads(response.text)
        except (json.JSONDecodeError, ValueError):
            raise AmbiguousMint("The service returned an unreadable response.") from None

    @staticmethod
    def _transport_failure(err: Exception) -> AmbiguousMint:
        # Transport failures are ambiguous for a mutating request: the request
        # may well have arrived, and only the answer was lost.
        if isinstance(err, httpx.TimeoutException):
            return AmbiguousMint(
                "The service took too long to respond - its answer, if any, was lost."
            )
        return AmbiguousMint(
            "Failed to reach the service - it may be offline or unreachable."
        )

    def _attempts(self, request: Request) -> int:
        """How many times this request may be re-sent after the first try.

        Only a rotate, split or merge - the mutations LUD-25's replay rule
        covers, which is what makes re-sending safe rather than a second burn.
        A read has nothing to resolve by asking again, and a melt has no replay
        guarantee at all.

        The same Request goes out each time rather than a rebuilt one: the
        replay is matched on the notes the k1s open, p1, p2 and amount, so a
        regenerated secret would make the retry a DIFFERENT mutation.
        """
        return self.mutation_retries if request.replayable else 0

    @staticmethod
    def _preserve(request: Request, err: BaseException) -> BaseException:
        """Attach a mutation's fresh secrets to whatever it failed with.

        Three families need them. An ambiguous outcome, because the request may
        have landed and they would then be the only copies of the notes the
        SERVICE minted. An unverifiable one, because it certainly landed. And a
        spent-or-unknown refusal, because at a SERVICE that has not implemented
        LUD-25's replay rule that refusal is also what an already-applied
        mutation looks like.

        A refusal on policy grounds burned nothing, so it carries nothing and
        the caller may discard its staged records at once.
        """
        if not request.new_secrets:
            return err
        if isinstance(err, AmbiguousMint):
            return AmbiguousMutation(str(err), request.new_secrets)
        if isinstance(err, (UnverifiableNote, NoteSpent, NoteUnknown)):
            err.new_secrets = request.new_secrets
        return err


class LnurlcashClient(_Base):
    """Synchronous client."""

    def __init__(self, *, client: httpx.Client | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._client = client
        self._owned = client is None

    def _attempt(self, client: httpx.Client, request: Request) -> Any:
        try:
            response = client.get(request.url)
        except Exception as err:
            raise self._preserve(request, self._transport_failure(err)) from err
        try:
            body = self._decode(response)
        except AmbiguousMint as err:
            raise self._preserve(request, err) from None
        try:
            return request.parse(body)
        except LnurlcashError as err:
            raise self._preserve(request, err) from None

    def _run(self, request: Request) -> Any:
        self._guard(request.url)
        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            for attempt in range(self._attempts(request) + 1):
                try:
                    return self._attempt(client, request)
                except AmbiguousMint:
                    if attempt >= self._attempts(request):
                        raise
            raise AssertionError("unreachable")  # pragma: no cover
        finally:
            if self._owned:
                client.close()

    # ---- operations ----

    def fetch_note_info(self, url: str) -> WithdrawRequestInfo:
        return self._run(protocol.note_info_request(url, self.policy))

    def fetch_mint_address(self, url: str) -> MintAddressInfo:
        return self._run(protocol.mint_address_request(url))

    def melt_note(self, callback: str, k1: str, pr: str) -> MeltResult:
        return self._run(protocol.melt_request(callback, k1, pr))

    def rotate_note(self, callback: str, k1: str) -> RotateResult:
        return self._run(
            protocol.rotate_request(callback, k1, rng=self.rng, policy=self.policy)
        )

    def rotate_note_with_hash(self, callback: str, k1: str, h: str) -> MutationResult:
        return self._run(
            protocol.rotate_request_with_hash(callback, k1, h, self.policy)
        )

    def split_note(
        self, callback: str, k1s: list[str], amount_msat: int
    ) -> SplitResult:
        return self._run(
            protocol.split_request(
                callback, k1s, amount_msat, rng=self.rng, policy=self.policy
            )
        )

    def split_note_with_hash(
        self, callback: str, k1s: list[str], amount_msat: int, h: str, h2: str
    ) -> MutationResult:
        return self._run(
            protocol.split_request_with_hash(
                callback, k1s, amount_msat, h, h2, self.policy
            )
        )

    def merge_notes(self, callback: str, k1s: list[str]) -> RotateResult:
        return self._run(
            protocol.merge_request(callback, k1s, rng=self.rng, policy=self.policy)
        )

    def merge_notes_with_hash(
        self, callback: str, k1s: list[str], h: str
    ) -> MutationResult:
        return self._run(
            protocol.merge_request_with_hash(callback, k1s, h, self.policy)
        )

    def fetch_pay_request(self, url: str) -> PayRequestInfo:
        return self._run(protocol.pay_request_request(url))

    def request_invoice(self, pay_callback: str, amount_msat: int) -> InvoiceResult:
        """A plain LUD-06 invoice. Mints nothing: it names no output."""
        return self._run(protocol.invoice_request(pay_callback, amount_msat))

    def request_mint_invoice(
        self, pay_callback: str, amount_msat: int, mint_secret: str
    ) -> InvoiceResult:
        """An invoice that mints a note the caller already holds the secret to.

        **Persist ``mint_secret`` before paying the invoice this returns.** The
        SERVICE only ever learns its hash, so it cannot help reconstruct it,
        and a paid invoice whose secret was lost is a note nobody can spend.
        """
        return self._run(
            protocol.mint_invoice_request(pay_callback, amount_msat, mint_secret)
        )

    def fetch_invoice_verification(self, verify_url: str) -> VerifyResult:
        return self._run(protocol.verify_request(verify_url))

    def probe_burned_note(self, url: str) -> str:
        """After an AmbiguousMutation: did the burn actually happen?

        ``'live'`` the request never landed, so the fresh secrets minted
        nothing. ``'gone'`` the burn landed, and the carried secrets are the
        only money left. ``'unknown'`` the probe itself failed - no
        information, so keep everything.
        """
        try:
            self.fetch_note_info(url)
            return "live"
        except (NoteSpent, NoteUnknown):
            return "gone"
        except Exception:
            return "unknown"

    def settle_note(
        self,
        base_url: str,
        k1: str,
        expected_amount_msat: int,
        signature: str | None = None,
    ) -> tuple[str, int, str | None, str]:
        """Resolve what a split's change or a merge's output is ACTUALLY worth,
        then rotate it before further use.

        Neither response carries an amount - the spec's only source of truth is
        an informational GET - and a fee-charging SERVICE may have deducted
        from a split's change or refunded into a merge's result. That GET puts
        k1 on the wire, so a rotate follows, best-effort.

        Returns ``(k1, amount_msat, signature, callback)``.
        """
        info = self.fetch_note_info(
            with_new_k1(base_url, k1, expected_amount_msat, signature)
        )
        try:
            rotated = self.rotate_note(info.callback, k1)
        except LnurlcashError as err:
            # Best-effort covers a refusal that burned nothing. It must not
            # cover a rotate that MAY HAVE LANDED: the SERVICE would then have
            # burned this k1 and minted the rotated note under h, whose only
            # copy is the fresh secret carried on the error. Returning the old
            # k1 there hands back a dead secret and drops the live one.
            # new_secrets_of is non-empty for exactly those cases - ambiguous,
            # unverifiable, or a spent/unknown refusal, which is also what an
            # already-applied mutation looks like asked a second time.
            if isinstance(err, AmbiguousMint) or new_secrets_of(err):
                raise
            return (k1, info.max_withdrawable, signature, info.callback)
        return (rotated.k1, info.max_withdrawable, rotated.signature, info.callback)


class AsyncLnurlcashClient(_Base):
    """Asynchronous client. Identical semantics to :class:`LnurlcashClient`."""

    def __init__(
        self, *, client: httpx.AsyncClient | None = None, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self._client = client
        self._owned = client is None

    async def _attempt(self, client: httpx.AsyncClient, request: Request) -> Any:
        try:
            response = await client.get(request.url)
        except Exception as err:
            raise self._preserve(request, self._transport_failure(err)) from err
        try:
            body = self._decode(response)
        except AmbiguousMint as err:
            raise self._preserve(request, err) from None
        try:
            return request.parse(body)
        except LnurlcashError as err:
            raise self._preserve(request, err) from None

    async def _run(self, request: Request) -> Any:
        self._guard(request.url)
        client = self._client or httpx.AsyncClient(timeout=self.timeout)
        try:
            for attempt in range(self._attempts(request) + 1):
                try:
                    return await self._attempt(client, request)
                except AmbiguousMint:
                    if attempt >= self._attempts(request):
                        raise
            raise AssertionError("unreachable")  # pragma: no cover
        finally:
            if self._owned:
                await client.aclose()

    async def fetch_note_info(self, url: str) -> WithdrawRequestInfo:
        return await self._run(protocol.note_info_request(url, self.policy))

    async def fetch_mint_address(self, url: str) -> MintAddressInfo:
        return await self._run(protocol.mint_address_request(url))

    async def melt_note(self, callback: str, k1: str, pr: str) -> MeltResult:
        return await self._run(protocol.melt_request(callback, k1, pr))

    async def rotate_note(self, callback: str, k1: str) -> RotateResult:
        return await self._run(
            protocol.rotate_request(callback, k1, rng=self.rng, policy=self.policy)
        )

    async def rotate_note_with_hash(
        self, callback: str, k1: str, h: str
    ) -> MutationResult:
        return await self._run(
            protocol.rotate_request_with_hash(callback, k1, h, self.policy)
        )

    async def split_note(
        self, callback: str, k1s: list[str], amount_msat: int
    ) -> SplitResult:
        return await self._run(
            protocol.split_request(
                callback, k1s, amount_msat, rng=self.rng, policy=self.policy
            )
        )

    async def split_note_with_hash(
        self, callback: str, k1s: list[str], amount_msat: int, h: str, h2: str
    ) -> MutationResult:
        return await self._run(
            protocol.split_request_with_hash(
                callback, k1s, amount_msat, h, h2, self.policy
            )
        )

    async def merge_notes(self, callback: str, k1s: list[str]) -> RotateResult:
        return await self._run(
            protocol.merge_request(callback, k1s, rng=self.rng, policy=self.policy)
        )

    async def merge_notes_with_hash(
        self, callback: str, k1s: list[str], h: str
    ) -> MutationResult:
        return await self._run(
            protocol.merge_request_with_hash(callback, k1s, h, self.policy)
        )

    async def fetch_pay_request(self, url: str) -> PayRequestInfo:
        return await self._run(protocol.pay_request_request(url))

    async def request_invoice(
        self, pay_callback: str, amount_msat: int
    ) -> InvoiceResult:
        """A plain LUD-06 invoice. Mints nothing: it names no output."""
        return await self._run(protocol.invoice_request(pay_callback, amount_msat))

    async def request_mint_invoice(
        self, pay_callback: str, amount_msat: int, mint_secret: str
    ) -> InvoiceResult:
        """An invoice that mints a note the caller already holds the secret to.

        **Persist ``mint_secret`` before paying the invoice this returns.**
        """
        return await self._run(
            protocol.mint_invoice_request(pay_callback, amount_msat, mint_secret)
        )

    async def fetch_invoice_verification(self, verify_url: str) -> VerifyResult:
        return await self._run(protocol.verify_request(verify_url))

    async def probe_burned_note(self, url: str) -> str:
        try:
            await self.fetch_note_info(url)
            return "live"
        except (NoteSpent, NoteUnknown):
            return "gone"
        except Exception:
            return "unknown"

    async def settle_note(
        self,
        base_url: str,
        k1: str,
        expected_amount_msat: int,
        signature: str | None = None,
    ) -> tuple[str, int, str | None, str]:
        info = await self.fetch_note_info(
            with_new_k1(base_url, k1, expected_amount_msat, signature)
        )
        try:
            rotated = await self.rotate_note(info.callback, k1)
        except LnurlcashError as err:
            # See the synchronous settle_note: a rotate that may have landed
            # must not be reported as a settled note.
            if isinstance(err, AmbiguousMint) or new_secrets_of(err):
                raise
            return (k1, info.max_withdrawable, signature, info.callback)
        return (rotated.k1, info.max_withdrawable, rotated.signature, info.callback)
