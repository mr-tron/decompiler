"""Interpretable compiler ranking; scores are evidence weights, not calibrated probabilities."""
from collections import Counter, defaultdict
import math
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path

from .asm import AsmError, parse_asm, walk


def features(asm: str) -> Counter:
    opcodes = [i.opcode for i in walk(parse_asm(asm).instructions)]
    return Counter(tuple(opcodes[i:i + n]) for n in (1, 2, 3)
                   for i in range(len(opcodes) - n + 1))


class Fingerprints:
    def __init__(self, rows=()):
        self.profiles = defaultdict(Counter)
        self.counts = Counter()
        self.errors = []
        training_identity = hashlib.sha256()
        for row in rows:
            if row.get('split') != 'train' or not row.get('success'):
                continue
            training_identity.update(json.dumps({key: row.get(key) for key in
                ('contract', 'group', 'version', 'toolchain_id', 'flags', 'asm')}, sort_keys=True).encode())
            key = (row['version'], tuple(row['flags']))
            try:
                observed = features(row['asm'])
            except AsmError as exc:
                self.errors.append({'contract': row['contract'], 'error': str(exc)})
                continue
            self.profiles[key].update(observed)
            self.counts[key] += 1
        self.training_sha256 = training_identity.hexdigest()

    def save(self, path):
        data = {'format': 1, 'training_sha256': self.training_sha256,
                'profiles': [{'version': key[0], 'flags': list(key[1]), 'examples': self.counts[key],
                              'features': [[list(feature), count] for feature, count in sorted(profile.items())]}
                             for key, profile in sorted(self.profiles.items())], 'errors': self.errors}
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + '.tmp')
        temporary.write_text(json.dumps(data, separators=(',', ':')) + '\n')
        temporary.replace(path)

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text())
        if data.get('format') != 1:
            raise ValueError('unsupported fingerprint profile format')
        model = cls()
        model.training_sha256 = data['training_sha256']
        model.errors = data.get('errors', [])
        for row in data['profiles']:
            key = (row['version'], tuple(row['flags']))
            model.profiles[key] = Counter({tuple(feature): count for feature, count in row['features']})
            model.counts[key] = row['examples']
        return model

    def rank(self, asm: str, configurations=()) -> list[dict]:
        observed = features(asm)
        keys = set(self.profiles) | {(v, tuple(f)) for v, f in configurations}
        scores = {}
        norm = math.sqrt(sum(v * v for v in observed.values()))
        for key in sorted(keys):
            profile = self.profiles[key]
            denominator = norm * math.sqrt(sum(v * v for v in profile.values()))
            scores[key] = sum(v * profile[k] for k, v in observed.items()) / denominator if denominator else 0
        total = sum(scores.values())
        return [{'version': key[0], 'flags': list(key[1]),
                 'score': value, 'weight': value / total if total else 1 / len(keys),
                 'evidence': 'training opcode 1/2/3-gram cosine; uncalibrated' if self.counts[key]
                 else 'no training evidence; compatibility untested'}
                for key, value in sorted(scores.items(), key=lambda item: (-item[1], item[0]))]


def differential_report(rows: list[dict]) -> dict:
    """Compare only the same source across toolchains, never unrelated contracts."""
    sources = defaultdict(list)
    for row in rows:
        if row.get('success'):
            sources[row['contract']].append(row)
    differences, ambiguous = [], []
    changes = defaultdict(set)
    opcode_cache = {}
    version_sensitive = optimizer_sensitive = 0
    for name, results in sorted(sources.items()):
        hashes = defaultdict(list)
        by_flags, by_version = defaultdict(set), defaultdict(set)
        for row in results:
            by_flags[tuple(row['flags'])].add(row['code_hash'])
            by_version[row.get('toolchain_id', row['version'])].add(row['code_hash'])
            hashes[row['code_hash']].append({'version': row['version'], 'flags': row['flags']})
        version_sensitive += any(len(values) > 1 for values in by_flags.values())
        optimizer_sensitive += any(len(values) > 1 for values in by_version.values())
        if any(len(values) > 1 for values in hashes.values()):
            ambiguous.append({'contract': name, 'equivalent_configurations': list(hashes.values())})
        if len(hashes) > 1:
            differences.append({'contract': name, 'distinct_code_hashes': len(hashes),
                                'configurations': len(results)})
            if results[0].get('split') == 'train':
                distinct = {r['code_hash']: r for r in results}
                baseline = results[0]
                for result in distinct.values():
                    try:
                        for row in (baseline, result):
                            if row['code_hash'] not in opcode_cache:
                                opcode_cache[row['code_hash']] = [i.opcode for i in walk(parse_asm(row['asm']).instructions)]
                        before, after = opcode_cache[baseline['code_hash']], opcode_cache[result['code_hash']]
                    except AsmError:
                        continue
                    for kind, a, b, c, d in SequenceMatcher(None, before, after).get_opcodes():
                        if kind != 'equal' and b - a <= 12 and d - c <= 12:
                            axes = ('version' if baseline['version'] != result['version'] else '') + ('+optimizer' if baseline['flags'] != result['flags'] else '')
                            pattern = (tuple(before[a:b]), tuple(after[c:d]), axes.strip('+') or 'same_metadata_distinct_binary')
                            changes[pattern].add(result.get('group', name))

    return {'successful_sources': len(sources), 'version_sensitive_sources': version_sensitive,
            'optimizer_sensitive_sources': optimizer_sensitive, 'differing_sources': differences,
            'ambiguous_sources': ambiguous,
            'development_instruction_changes': [
                {'before': list(pattern[0]), 'after': list(pattern[1]), 'changed_axes': pattern[2], 'support_source_groups': len(groups)}
                for pattern, groups in sorted(changes.items(), key=lambda item: (-len(item[1]), item[0]))[:40]],
            'conclusion': 'Identical output cannot distinguish compiler version or flags. '
                          'Opcode ranking is uncalibrated and must be checked by recompilation.'}


def evaluate_fingerprints(rows: list[dict]) -> dict:
    model = Fingerprints(rows)
    results = []
    eligible = sum(row.get('split') == 'holdout' and row.get('success', False) for row in rows)
    for row in rows:
        if row.get('split') != 'holdout' or not row.get('success'):
            continue
        try:
            candidates = model.rank(row['asm'])
        except AsmError:
            continue
        if not candidates:
            continue
        best = candidates[0]['score']
        tied = [c for c in candidates if abs(c['score'] - best) < 1e-12]
        versions = {c['version'] for c in tied}
        exact = [c for c in tied if c['version'] == row['version'] and c['flags'] == row['flags']]
        results.append({'contract': row['contract'], 'version': row['version'], 'flags': row['flags'],
                        'version_exact': len(versions) == 1 and row['version'] in versions,
                        'version_top_set': row['version'] in versions,
                        'configuration_exact': len(tied) == 1 and bool(exact),
                        'configuration_top_set': bool(exact), 'tied_configurations': len(tied)})
    keys = ('version_exact', 'version_top_set', 'configuration_exact', 'configuration_top_set')
    return {'observations': len(results), 'eligible_observations': eligible,
            'unclassified_observations': eligible - len(results), 'training_parse_failures': model.errors,
            'rates': {key: sum(r[key] for r in results) / eligible if eligible else 0 for key in keys},
            'interpretation': 'Held-out compilation-configuration classification, not proof of historical provenance. '
                              'Top-set recall includes ties; exact accuracy requires a unique prediction.',
            'results': results}
