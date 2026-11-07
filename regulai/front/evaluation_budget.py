"""Durable, single-host reservation ledger for explicitly authorized real tests."""
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit
import uuid


class BudgetExceeded(ValueError):
    pass


def money(value):
    value = Decimal(str(value))
    if not value.is_finite() or value < 0:
        raise ValueError('Invalid nonnegative amount')
    return value


class EvaluationBudget:
    """All test invocations share one file. Uncertain outcomes retain reservation."""
    def __init__(self, path, cap, *, authorization_id=None, authorization_digest=None):
        self.path, self.cap = str(path), money(cap)
        self.authorization = (authorization_id, authorization_digest) if authorization_id is not None else None
        self.run_id = None
        if self.cap <= 0:
            raise ValueError('A positive total ceiling is required.')
        with self.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS authorization (cap TEXT NOT NULL)')
            caps = db.execute('SELECT cap FROM authorization').fetchall()
            if len(caps) > 1:
                raise ValueError('The ledger has an ambiguous budget anchor.')
            previous = caps[0] if caps else None
            if not previous:
                if self.cap > 1:
                    raise ValueError('A new pilot is capped at 1 USD; extend its authorization explicitly.')
                db.execute('INSERT INTO authorization VALUES (?)', (str(self.cap),))
            db.execute('CREATE TABLE IF NOT EXISTS calls (id TEXT PRIMARY KEY, at TEXT, purpose TEXT, '
                       'reserved TEXT, status TEXT, cost TEXT, metadata TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS approval (id TEXT NOT NULL, digest TEXT NOT NULL)')
            approval = self.head(db)
            if authorization_id is not None:
                if not authorization_id or not authorization_digest:
                    raise ValueError('An explicit authorization identity and digest are required.')
                if approval and approval != (authorization_id, authorization_digest):
                    raise ValueError('The existing authorization cannot be replaced or renewed implicitly.')
                if not approval:
                    if db.execute('SELECT 1 FROM calls LIMIT 1').fetchone():
                        raise ValueError('Historical calls cannot acquire a new authorization.')
                    db.execute('INSERT INTO approval VALUES (?,?)', (authorization_id, authorization_digest))
            elif approval:
                raise ValueError('This ledger requires its explicit authorization.')
            terms = self.campaign_terms(db, approval)
            effective_cap = money(terms['approved_ceiling_usd']) if terms else money(previous[0]) if previous else self.cap
            if self.cap != effective_cap:
                raise ValueError('Existing authorization limit cannot be changed implicitly.')

    @staticmethod
    def campaign_terms(db, authorization):
        if authorization and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='campaign_terms'").fetchone():
            row = db.execute('SELECT terms FROM campaign_terms WHERE authorization_id=? AND authorization_digest=?',
                             authorization).fetchone()
            if row:
                return json.loads(row[0])
        return None

    @staticmethod
    def utc_time(value):
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
        if not isinstance(parsed, datetime) or parsed.tzinfo is None:
            raise ValueError('Authorization times must include a timezone.')
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def validate_provenance(value):
        if not isinstance(value, dict):
            raise ValueError('Dated source provenance is required.')
        url = urlsplit(value.get('source_url', ''))
        digest = value.get('sha256', '')
        if (url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment
                or len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest)):
            raise ValueError('Provenance requires an HTTPS source and SHA-256 digest.')
        from datetime import date
        date.fromisoformat(value.get('date', ''))

    @classmethod
    def validated_campaign_terms(cls, *, approved_ceiling_usd, approved_ceiling_eur,
            starts_at, expires_at, fx_provenance, price_provenance, margin):
        """Validate serialized terms without reading or writing any ledger."""
        cap, euros, margin = money(approved_ceiling_usd), money(approved_ceiling_eur), money(margin)
        cls.validate_provenance(fx_provenance)
        rate = money(fx_provenance.get('rate_usd_per_eur'))
        if not isinstance(price_provenance, list) or not price_provenance:
            raise ValueError('Official price provenance is required.')
        for source in price_provenance:
            cls.validate_provenance(source)
        start, end = cls.utc_time(starts_at), cls.utc_time(expires_at)
        if (not 0 < euros <= 2 or cap <= 0 or rate <= 0 or cap > euros * rate / (1 + margin)
                or not 0 < (end - start).total_seconds() <= 86400):
            raise ValueError('The approved aggregate ceiling, conversion or 24-hour window is invalid.')
        return {'approved_ceiling_usd': str(cap), 'approved_ceiling_eur': str(euros),
            'starts_at': start.isoformat(), 'expires_at': end.isoformat(), 'margin': str(margin),
            'fx_provenance': fx_provenance, 'price_provenance': price_provenance}

    @classmethod
    def extend_campaign_authorization(cls, path, *, previous_id, previous_digest, authorization_id,
            authorization_digest, manifest_sha256, approval_reference, max_external_calls,
            approved_ceiling_usd, approved_ceiling_eur, starts_at, expires_at, fx_provenance,
            price_provenance, margin):
        """Append explicit terms; never rewrite historical balances or reservations."""
        terms = cls.validated_campaign_terms(approved_ceiling_usd=approved_ceiling_usd,
            approved_ceiling_eur=approved_ceiling_eur, starts_at=starts_at, expires_at=expires_at,
            fx_provenance=fx_provenance, price_provenance=price_provenance, margin=margin)
        cap = money(terms['approved_ceiling_usd'])
        ledger = cls.__new__(cls)
        ledger.path = str(path)
        with ledger.transaction(existing_only=True) as db:
            caps = db.execute('SELECT cap FROM authorization').fetchall()
            if len(caps) != 1:
                raise ValueError('An immutable existing budget anchor is required.')
            head = cls.head(db)
            existing = cls.campaign_terms(db, (authorization_id, authorization_digest))
            if existing is not None and existing != terms:
                raise ValueError('Approved campaign terms cannot be replaced.')
            if existing is None and head == (authorization_id, authorization_digest):
                raise ValueError('A historical scope cannot acquire a larger ceiling retroactively.')
            previous_terms = cls.campaign_terms(db, head)
            old_cap = money(previous_terms['approved_ceiling_usd']) if previous_terms else money(caps[0][0])
            if cap < old_cap:
                raise ValueError('A ceiling extension cannot reduce the existing approved ceiling.')
            used = sum((cls.exposure(bound, cost, json.loads(meta)) for bound, cost, meta
                        in db.execute('SELECT reserved,cost,metadata FROM calls')), Decimal(0))
            if used > cap:
                raise BudgetExceeded('Historical exposure exceeds the proposed aggregate ceiling.')
            added = cls.append_extension(db, previous_id=previous_id, previous_digest=previous_digest,
                authorization_id=authorization_id, authorization_digest=authorization_digest,
                manifest_sha256=manifest_sha256, approval_reference=approval_reference,
                max_external_calls=max_external_calls)
            db.execute('CREATE TABLE IF NOT EXISTS campaign_terms (authorization_id TEXT PRIMARY KEY, '
                       'authorization_digest TEXT NOT NULL UNIQUE, terms TEXT NOT NULL)')
            if existing is None:
                db.execute('INSERT INTO campaign_terms VALUES (?,?,?)',
                    (authorization_id, authorization_digest, json.dumps(terms, sort_keys=True)))
        return added

    @staticmethod
    def head(db):
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='approval_extensions'").fetchone():
            latest = db.execute('SELECT id,digest FROM approval_extensions ORDER BY sequence DESC LIMIT 1').fetchone()
            if latest:
                return latest
        anchors = db.execute('SELECT id,digest FROM approval').fetchall()
        if len(anchors) > 1:
            raise ValueError('The ledger has an ambiguous approval anchor.')
        return anchors[0] if anchors else None

    @classmethod
    def append_extension(cls, db, *, previous_id, previous_digest, authorization_id,
                         authorization_digest, manifest_sha256, approval_reference, max_external_calls):
        values = (previous_id, previous_digest, authorization_id, authorization_digest,
                  manifest_sha256, approval_reference)
        if (any(not isinstance(value, str) or not value for value in values)
                or len(manifest_sha256) != 64 or any(char not in '0123456789abcdef' for char in manifest_sha256)
                or previous_id == authorization_id or previous_digest == authorization_digest
                or type(max_external_calls) is not int or max_external_calls < 1):
            raise ValueError('Invalid explicit scope extension.')
        head = cls.head(db)
        if not head:
            raise ValueError('An explicit existing approval is required.')
        db.execute('CREATE TABLE IF NOT EXISTS approval_extensions ('
            'sequence INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL UNIQUE, '
            'previous_id TEXT NOT NULL, previous_digest TEXT NOT NULL, at TEXT NOT NULL, '
            'manifest_sha256 TEXT NOT NULL, approval_reference TEXT NOT NULL, max_external_calls INTEGER NOT NULL, '
            'UNIQUE(previous_id, previous_digest))')
        expected = (authorization_id, authorization_digest, previous_id, previous_digest,
                    manifest_sha256, approval_reference, max_external_calls)
        duplicate = db.execute('SELECT id,digest,previous_id,previous_digest,manifest_sha256,'
            'approval_reference,max_external_calls FROM approval_extensions WHERE id=? OR digest=?',
            (authorization_id, authorization_digest)).fetchone()
        if duplicate:
            if duplicate == expected and head == (authorization_id, authorization_digest):
                return False
            raise ValueError('A scope identity cannot be reused or replaced.')
        if head != (previous_id, previous_digest):
            raise ValueError('The previous approval is not the current ledger head.')
        anchors = db.execute('SELECT id,digest FROM approval').fetchall()
        if any(authorization_id == pair[0] or authorization_digest == pair[1] for pair in anchors):
            raise ValueError('The original approval cannot be reused.')
        db.execute('INSERT INTO approval_extensions (id,digest,previous_id,previous_digest,manifest_sha256,'
            'approval_reference,max_external_calls,at) VALUES (?,?,?,?,?,?,?,?)',
            (*expected, datetime.now(timezone.utc).isoformat()))
        db.execute('CREATE TABLE IF NOT EXISTS extension_runs (authorization_id TEXT PRIMARY KEY, '
            'run_id TEXT NOT NULL UNIQUE, manifest_sha256 TEXT NOT NULL, at TEXT NOT NULL)')
        return True

    @classmethod
    def extend_authorization(cls, path, cap, *, previous_id, previous_digest, authorization_id,
                             authorization_digest, manifest_sha256, approval_reference, max_external_calls):
        """Append an explicitly validated legacy scope, retaining its original cap."""
        ledger = cls.__new__(cls)
        ledger.path, ledger.cap = str(path), money(cap)
        try:
            with ledger.transaction(existing_only=True) as db:
                caps = db.execute('SELECT cap FROM authorization').fetchall()
                if len(caps) != 1 or money(caps[0][0]) != ledger.cap or not 0 < ledger.cap <= 1:
                    raise ValueError('The shared authorization cap cannot change.')
                if cls.campaign_terms(db, cls.head(db)):
                    raise ValueError('A campaign scope requires explicit campaign terms, including its window.')
                return cls.append_extension(db, previous_id=previous_id, previous_digest=previous_digest,
                    authorization_id=authorization_id, authorization_digest=authorization_digest,
                    manifest_sha256=manifest_sha256, approval_reference=approval_reference,
                    max_external_calls=max_external_calls)
        except sqlite3.Error as error:
            raise ValueError('The existing ledger cannot accept this scope extension.') from error

    def check_active(self, db):
        if self.head(db) != self.authorization:
            raise ValueError('The approval is no longer the current ledger head.')
        terms = self.campaign_terms(db, self.authorization)
        if terms:
            if money(terms['approved_ceiling_usd']) != self.cap:
                raise ValueError('The active approved ceiling changed.')
            if not self.utc_time(terms['starts_at']) <= datetime.now(timezone.utc) < self.utc_time(terms['expires_at']):
                raise BudgetExceeded('The approved campaign window is not active.')

    def claim_extension_run(self, manifest_sha256):
        """A claimed extension cannot resume/replay, even after a crash or new output directory."""
        with self.transaction() as db:
            self.check_active(db)
            extension = db.execute('SELECT manifest_sha256 FROM approval_extensions WHERE id=? AND digest=?',
                                   self.authorization).fetchone()
            if not extension or extension[0] != manifest_sha256:
                raise ValueError('The run must use the registered extension manifest.')
            if db.execute('SELECT 1 FROM extension_runs WHERE authorization_id=?', (self.authorization[0],)).fetchone():
                raise ValueError('This extension run was already claimed; automatic replay is prohibited.')
            run_id = str(uuid.uuid4())
            db.execute('INSERT INTO extension_runs VALUES (?,?,?,?)',
                       (self.authorization[0], run_id, manifest_sha256, datetime.now(timezone.utc).isoformat()))
        self.run_id = run_id
        return run_id

    @contextmanager
    def transaction(self, *, existing_only=False):
        location = Path(self.path).resolve().as_uri() + '?mode=rw' if existing_only else self.path
        db = sqlite3.connect(location, timeout=10, uri=existing_only)
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def reserve(self, purpose, maximum, *, metadata=None, zero_cost=False, authorize=None):
        maximum = money(maximum)
        if maximum == 0 and not zero_cost:
            raise ValueError('A positive reservation is required.')
        with self.transaction() as db:
            # Re-read approval only after the writer lock has been acquired.
            # No network or nested ledger transaction belongs in this callback.
            if authorize:
                authorize()
            self.check_active(db)
            metadata = dict(metadata or {})
            if self.authorization:
                metadata.update(authorization_id=self.authorization[0], authorization_digest=self.authorization[1])
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='approval_extensions'").fetchone():
                extension = db.execute('SELECT manifest_sha256,max_external_calls FROM approval_extensions WHERE id=? AND digest=?',
                                       self.authorization or (None, None)).fetchone()
                if extension:
                    claimed = db.execute('SELECT run_id FROM extension_runs WHERE authorization_id=?',
                                         (self.authorization[0],)).fetchone()
                    if not self.run_id or claimed != (self.run_id,):
                        raise ValueError('Reserve calls only in the process that claimed this extension run.')
                    metadata.update(manifest_sha256=extension[0], run_id=self.run_id)
                    external = not (purpose == 'obfuscation' and zero_cost and metadata.get('transport') == 'local')
                    metadata['scope_external_call'] = external
                    previous_calls = [json.loads(row[0]) for row in db.execute('SELECT metadata FROM calls')]
                    count = sum(row.get('authorization_id') == self.authorization[0]
                                and row.get('scope_external_call') is True for row in previous_calls)
                    if external and count >= extension[1]:
                        raise BudgetExceeded('The approved external call count is exhausted.')
            if db.execute("SELECT 1 FROM calls WHERE status='bound_exceeded' LIMIT 1").fetchone():
                raise BudgetExceeded('An earlier provider charge exceeded its bound; review required.')
            used = sum((self.exposure(bound, cost, json.loads(meta))
                for bound, cost, meta in db.execute('SELECT reserved,cost,metadata FROM calls')), Decimal(0))
            if used + maximum > self.cap:
                raise BudgetExceeded('Authorized total budget exhausted.')
            call_id = str(uuid.uuid4())
            db.execute('INSERT INTO calls VALUES (?,?,?,?,?,?,?)', (call_id,
                datetime.now(timezone.utc).isoformat(), purpose, str(maximum), 'started', None, json.dumps(metadata)))
        return call_id

    @staticmethod
    def exposure(bound, cost, metadata):
        # A tariff calculation is an estimate, not a communicated charge. It
        # never releases the reservation merely because it happens to be lower.
        if cost is not None and metadata.get('cost_kind', 'provider_reported') in ('provider_reported', 'configured_zero', 'not_incurred'):
            return money(cost)
        return max(money(bound), money(cost) if cost is not None else Decimal(0))

    def complete(self, call_id, *, cost=None, metadata=None, status='completed', cost_kind='provider_reported'):
        if status not in {'completed', 'failed', 'outcome_unknown', 'not_started'} or cost_kind not in {
                'provider_reported', 'tariff_estimate', 'configured_zero', 'not_incurred', 'unknown'}:
            raise ValueError('Invalid settlement status or cost provenance.')
        with self.transaction() as db:
            row = db.execute('SELECT reserved,status,metadata FROM calls WHERE id=?', (call_id,)).fetchone()
            if not row or row[1] != 'started':
                raise ValueError('Call is missing or already settled.')
            cost = money(cost) if cost is not None else None
            if (status == 'not_started' or cost_kind == 'not_incurred') and not (
                    status == 'not_started' and cost_kind == 'not_incurred' and cost == 0):
                raise ValueError('A non-started call must have a proven zero expense.')
            if cost_kind == 'configured_zero' and (cost != 0 or money(row[0]) != 0):
                raise ValueError('Configured zero requires a zero bound and zero cost.')
            if status != 'completed':
                cost_kind = 'unknown' if cost is None else cost_kind
            # Record even a provider charge exceeding its advertised bound, then
            # stop further tests; never erase an observed expense.
            if cost is not None and cost > money(row[0]):
                status = 'bound_exceeded'
            original_metadata = json.loads(row[2])
            settled_metadata = {**original_metadata, **(metadata or {}), 'cost_kind': cost_kind}
            for field in ('authorization_id', 'authorization_digest', 'manifest_sha256', 'run_id', 'transport', 'scope_external_call'):
                if field in original_metadata:
                    settled_metadata[field] = original_metadata[field]
            db.execute('UPDATE calls SET status=?,cost=?,metadata=? WHERE id=?',
                (status, str(cost) if cost is not None else None,
                 json.dumps(settled_metadata), call_id))
        if status == 'bound_exceeded':
            raise BudgetExceeded('Provider charge exceeded the reserved bound.')

    def snapshot(self):
        with self.transaction() as db:
            rows = db.execute('SELECT id,at,purpose,reserved,status,cost,metadata FROM calls ORDER BY rowid').fetchall()
        calls = [dict(zip(('id','at','purpose','reserved','status','cost','metadata'), row)) for row in rows]
        for call in calls:
            call['metadata'] = json.loads(call['metadata'])
        known = sum((money(call['cost']) for call in calls if call['cost'] is not None), Decimal(0))
        uncertain = sum((money(call['reserved']) for call in calls if call['cost'] is None), Decimal(0))
        exposure = sum((self.exposure(call['reserved'], call['cost'], call['metadata']) for call in calls), Decimal(0))
        reported = sum((money(call['cost']) for call in calls if call['cost'] is not None
                        and call['metadata'].get('cost_kind') == 'provider_reported'), Decimal(0))
        estimated = sum((money(call['cost']) for call in calls if call['cost'] is not None
                         and call['metadata'].get('cost_kind') == 'tariff_estimate'), Decimal(0))
        return {'cap_usd': str(self.cap), 'known_cost_usd': str(known),
            'provider_reported_usd': str(reported), 'tariff_estimated_usd': str(estimated),
            'budget_exposure_usd': str(exposure), 'remaining_usd': str(max(Decimal(0), self.cap - exposure)),
            'uncertain_reservations_usd': str(uncertain), 'calls': calls}
