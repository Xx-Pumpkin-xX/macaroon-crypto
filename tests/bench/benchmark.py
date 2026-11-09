"""Reproducible microbenchmarks; run from any directory, no stored secrets."""
import argparse
import csv
import importlib.metadata
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT_DIR = ROOT
sys.path.insert(0, str(PROJECT_DIR / 'backend' / 'pymacaroons'))
sys.path.insert(0, str(PROJECT_DIR / 'backend'))
os.environ.setdefault('MPLCONFIGDIR', '/tmp/macaroon-matplotlib')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pymacaroons import Macaroon, Verifier
from macaroon_core import tokens, caveats, errors


def measure(call, samples, batch):
    for _ in range(5):
        call()
    values = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        for _ in range(batch):
            call()
        values.append((time.perf_counter_ns() - start) / batch / 1000)
    return statistics.median(values), values


def write_csv(path, rows):
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys(), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--samples', type=int, default=31)
    parser.add_argument('--batch', type=int, default=50)
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/results')
    args = parser.parse_args()
    if args.samples < 1 or args.batch < 1:
        parser.error('samples and batch must be positive')
    args.output.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    file_id = 'AAAAAAAAAAAAAAAAAAAAAA'
    rows, raw = [], []
    for n in range(1, 51):
        m = Macaroon(location=tokens.TOKEN_LOCATION, identifier=file_id, key=key)
        # Same grammar and workload at every count: one op + repeated expiry.
        for text in ['op = read'] + ['expires < 1900000000'] * (n - 1):
            m.add_first_party_caveat(text)
        serialized = m.serialize()
        def library_verify():
            decoded = Macaroon.deserialize(serialized)
            verifier = Verifier()
            verifier.satisfy_general(caveats.is_known_caveat)
            verifier.verify(decoded, key)
        library_us, values = measure(library_verify, args.samples, args.batch)
        raw.append({'count': n, 'layer': 'library_decode_hmac_syntax', 'us': values})
        core_us = ''
        if n <= tokens.MAX_CAVEATS:
            core_us, values = measure(lambda: tokens.verify_token(serialized, file_id, key, now=1800000000), args.samples, args.batch)
            raw.append({'count': n, 'layer': 'application_full_verify', 'us': values})
        else:
            try:
                tokens.verify_token(serialized, file_id, key, now=1800000000)
            except errors.InvalidToken:
                pass
            else:
                raise AssertionError('application accepted more than 20 caveats')
        rows.append(dict(caveats=n, token_bytes=len(serialized.encode()), library_verify_us=library_us, core_verify_us=core_us, application_accepted=n <= 20))
    write_csv(args.output / 'tokens.csv', rows)
    aes_rows = []
    aes = AESGCM(os.urandom(32))
    for size in (64, 1024, 16384, 65536, 262144, 1048548):
        data = os.urandom(size)
        # Unique nonce for each encryption; includes nonce generation cost.
        def encrypt():
            nonce = os.urandom(12)
            return nonce, aes.encrypt(nonce, data, None)
        nonce, ciphertext = encrypt()
        assert aes.decrypt(nonce, ciphertext, None) == data
        for operation, call in [('encrypt', encrypt), ('decrypt', lambda: aes.decrypt(nonce, ciphertext, None))]:
            us, values = measure(call, args.samples, args.batch)
            raw.append({'size': size, 'layer': operation, 'us': values})
            aes_rows.append(dict(plaintext_bytes=size, blob_bytes=size+28, operation=operation, median_us=us, throughput_mib_s=size/(1024**2)/(us/1e6)))
    write_csv(args.output / 'aes.csv', aes_rows)
    metadata = dict(platform=platform.platform(), processor=platform.processor() or next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'), python=sys.version, samples=args.samples, batch=args.batch, warmups=5, timer='perf_counter_ns', statistic='median of batch means', pymacaroons_source=str(Path(sys.modules['pymacaroons'].__file__).relative_to(PROJECT_DIR)), packages={p: importlib.metadata.version(p) for p in ('cryptography','matplotlib','pytest')}, measured_at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), workload='1 op, n-1 identical future expiry caveats; decoding included; core includes semantic evaluation; keys generated in memory; no I/O/network in timed sections', aes='Python cryptography AES-256-GCM; encrypt includes os.urandom(12); decrypt reuses a valid ciphertext; not browser WebCrypto')
    (args.output / 'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    (args.output / 'samples.json').write_text(json.dumps(raw, indent=2)+'\n')
    for column, title, ylabel, filename in [('token_bytes','Token size','Serialized bytes','token-size.png'), ('library_verify_us','HMAC verification','Microseconds','verify-time.png')]:
        fig, ax = plt.subplots(figsize=(7,4))
        ax.plot([r['caveats'] for r in rows], [r[column] for r in rows], label='Serialized macaroon' if column == 'token_bytes' else 'Library: decode + HMAC + syntax')
        if column == 'library_verify_us':
            ax.plot(list(range(1,21)), [r['core_verify_us'] for r in rows[:20]], label='Application: full verify')
        ax.axvline(20, linestyle='--', color='gray', label='Application limit: 20')
        ax.set(xlabel='Caveat count', ylabel=ylabel, title=title)
        ax.legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(args.output / filename, dpi=160)
        plt.close(fig)
    fig, ax = plt.subplots(figsize=(7,4))
    for operation in ('encrypt','decrypt'):
        subset = [r for r in aes_rows if r['operation'] == operation]
        ax.plot([r['plaintext_bytes'] for r in subset], [r['throughput_mib_s'] for r in subset], marker='o', label=operation)
    ax.set(xscale='log', xlabel='Plaintext bytes', ylabel='MiB/s', title='AES-256-GCM (Python cryptography)')
    ax.legend()
    fig.tight_layout()
    fig.savefig(args.output / 'aes-throughput.png', dpi=160)
    plt.close(fig)
    print('Wrote CSV, raw samples, metadata and three charts to', args.output)

if __name__ == '__main__':
    main()
