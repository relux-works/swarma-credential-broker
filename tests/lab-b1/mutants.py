"""Replay the PR #83 B1a fix-round source overlays in an isolated checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', required=True, type=Path)
parser.add_argument('--only', action='append', default=[])
arguments = parser.parse_args()
output = arguments.out
if not output.is_absolute():
    parser.error('--out must be absolute')
output.mkdir(parents=True, exist_ok=True, mode=0o700)
output = output.resolve()
scratch = output.parent
repository = Path.cwd().resolve()
if not repository.is_relative_to(scratch) or repository == scratch:
    parser.error('run from a populated isolated checkout beside --out')
for name in ('HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'GOCACHE', 'GOMODCACHE', 'GOPATH', 'TMPDIR', 'TMP', 'TEMP', 'GOTMPDIR'):
    value = Path(os.environ.get(name, ''))
    if not value.is_absolute() or not value.resolve().is_relative_to(scratch):
        parser.error(name+' must be absolute inside the same scratch root')
if (repository / 'go.mod').read_text().splitlines()[0] != 'module github.com/relux-works/swarma-credential-broker':
    parser.error('wrong source checkout')
cases = []

def add(name, test, source, old, new, extra=()):
    changed = {}
    edits = []
    for filename, before, after in [(source, old, new), *extra]:
        original = changed.get(filename, (repository / filename).read_text())
        if original.count(before) != 1:
            raise RuntimeError(name+': plant is absent or nonunique in '+filename)
        changed[filename] = original.replace(before, after)
        edits.append(dict(source=filename, old=before, new=after))
    replacements = {}
    for filename, content in changed.items():
        replacement = output / (name+'-'+Path(filename).name)
        replacement.write_text(content)
        replacements[str(repository / filename)] = str(replacement)
    overlay = output / (name+'.json')
    overlay.write_text(json.dumps({'Replace': replacements}, indent=2)+'\n')
    cases.append(dict(name=name, test=test, edits=edits, overlay=str(overlay)))

continued = 'internal/labv0/continued_linux.go'
add('publication-fence-overwrite', '^TestReviewFenceDuringPublishIsSticky$/during-publish$', continued,
    'if use.epoch != publicationEpoch {', 'if false && use.epoch != publicationEpoch {')
add('observation-clears-engine-unknown', '^TestReviewProbeObservationCommitClearsEngineUnknown$', continued,
    'if use.account.unknown {\n\t\treturn ErrUnknown\n\t}', 'if use.account.unknown {\n\t\tuse.account.unknown = false\n\t}')
add('publication-clears-engine-unknown', '^TestReviewProbePublicationCommitClearsEngineUnknown$', continued,
    'if use.account.unknown {\n\t\treturn ErrUnknown\n\t}', 'if use.account.unknown {\n\t\tuse.account.unknown = false\n\t}')

add('observation-never-reconciles', '^TestReviewD1NewPairReconcilesObservationUncertainty$', continued,
    'use.account.observationUncertain && !admittedPair', 'use.account.observationUncertain')
add('observation-single-reconciles', '^TestReviewD1NonPairCannotReconcile$/single-cas$', continued,
    'use.account.observationUncertain && !admittedPair', 'use.account.observationUncertain && false')
add('observation-cache-reconciles', '^TestReviewD1NonPairCannotReconcile$/cached-cas$', continued,
    'use.account.observationUncertain && !admittedPair', 'use.account.observationUncertain && false')
add('observation-engine-clears-own', '^TestReviewD1EngineUncertaintyAfterObservation$/engine-confirmation$',
    'internal/labv0/account_linux.go',
    'if account.records.Put(stateName, account.revision, envelope) != nil {\n\t\treturn ErrUnknown\n\t}\n\taccount.unknown = false',
    'if account.records.Put(stateName, account.revision, envelope) != nil {\n\t\treturn ErrUnknown\n\t}\n\taccount.unknown = false\n\taccount.observationUncertain = false')
add('observation-engine-takeover-ignored', '^TestReviewD1EngineUncertaintyAfterObservation$/engine-rename$', continued,
    'if use.account.unknown {\n\t\treturn ErrUnknown\n\t}', 'if use.account.unknown {\n\t\tuse.account.unknown = false\n\t}')
add('observation-restart-clears-own', '^TestReviewD1RestartRequiresPair$', continued,
    '\t\taccount.observationUncertain = true', '\t\taccount.observationUncertain = false')

add('publication-pre-cas-epoch', '^TestLabReviewFenceBeforeObservationCAS$', continued,
    'unchanged := use.epoch == publicationEpoch', 'unchanged := true || use.epoch == publicationEpoch')
add('publication-post-cas-epoch', '^TestReviewFenceDuringPublishIsSticky$/during-cas$', continued,
    'unchanged = use.epoch == publicationEpoch', 'unchanged = true || use.epoch == publicationEpoch')
add('initial-lateness', '^TestLabReviewInitialObservationWindow$', continued,
    'first.before >= receipt+int64(observationWindow+schedulerMargin)', 'false')
add('initial-cooldown', '^TestLabReviewInitialObservationWindow$', continued,
    'first.before < receipt+int64(observationWindow)', 'false')
add('current-age-ceiling', '^TestLabReviewCurrentAgePredicate$', continued,
    'now-observed < int64(nativeAge)', 'true')
add('current-age-future', '^TestLabReviewCurrentAgePredicate$', continued,
    'valid = now >= observed && now-observed', 'valid = true && now-observed')
outside_lock = 'if use.current() != nil {\n\t\treturn ErrUnknown\n\t}\n\tif !use.account.mu.TryLock() {\n\t\treturn ErrUnknown\n\t}\n\tdefer use.account.mu.Unlock()\n\tif err := use.commit'
inside_lock = 'if !use.account.mu.TryLock() {\n\t\treturn ErrUnknown\n\t}\n\tdefer use.account.mu.Unlock()\n\tif use.current() != nil {\n\t\treturn ErrUnknown\n\t}\n\tif err := use.commit'
add('containment-callback-under-lock', '^TestLabReviewContainmentCallbackLockOrder$', continued,
    outside_lock, inside_lock)
before_deadline = 'for _, deadline := range deadlines {\n\t\tif now >= deadline {\n\t\t\treturn ErrUnknown\n\t\t}\n\t}'
for phase, suffix in [('before-cas', '\n\trevision :='), ('after-cas', '\n\tuse.account.observationUncertain = false')]:
    for boundary, position in [('connection', 0), ('pair-budget', 1), ('native-age', 1)]:
        replacement = 'for position, deadline := range deadlines {\n\t\tif position != '+str(position)+' && now >= deadline {\n\t\t\treturn ErrUnknown\n\t\t}\n\t}'
        add('deadline-'+phase+'-'+boundary, '^TestLabReviewObservationCommitDeadlines$/'+boundary+'/', continued,
            before_deadline+suffix, replacement+suffix)
add('late-cas-publishes', '^TestLabReviewPublicationDeadlines$/late-cas$', continued,
    before_deadline+'\n\tuse.account.observationUncertain = false', before_deadline.replace('if now >= deadline {', 'if now >= deadline && false {')+'\n\tuse.account.observationUncertain = false')
add('late-single-cas', '^TestLabReviewPeriodicLateCAS$', continued,
    before_deadline+'\n\tuse.account.observationUncertain = false', before_deadline.replace('if now >= deadline {', 'if now >= deadline && false {')+'\n\tuse.account.observationUncertain = false')
add('late-publication-reopens', '^TestLabReviewPublicationDeadlines$/late-publish$', continued,
    'now >= final.deadline', 'now >= final.deadline && false')

recovery = 'internal/labv0/recovery_linux.go'
for name, predicate in [('held', 'external["held"] != active'), ('revoked', 'record["revoked"] != (binding.State == "removed")'), ('gateway-uid', 'gateway["uid"] != int64(binding.UID)'), ('gateway-generation', 'gateway["generation"] != binding.Generation'), ('state-revision', 'encoded["revision"].(int64) > revision')]:
    add('recovery-'+name, '^TestLabReviewRecoveryJoinPredicates$/'+name+'$', recovery, predicate, 'false')

client = 'internal/labv0/observation_linux.go'
for name, predicate in [('response-operation-id', 'record["operation_id"] != client.pins.start["operation_id"]'), ('response-start-id', 'record["start_id"] != client.pins.start["start_id"]'), ('future-observation', 'observed > sample.after/int64(time.Millisecond)')]:
    add(name, '^TestLabReviewObservationResponseJoins$/'+name+'$', client, predicate, 'false')
add('future-periodic-two-layer', '^TestLabObservationPeriodicAdversarialPairs$/future-observation$', client,
    'observed > sample.after/int64(time.Millisecond)', 'false',
    [(continued, 'record["observed_monotonic_ms"].(int64) <= record["receipt_monotonic_ms"].(int64)', 'true')])

expected_failures = {
    'observation-never-reconciles': 'new admitted pair could not reconcile observation uncertainty',
    'observation-single-reconciles': 'non-pair reconciled observation uncertainty',
    'observation-cache-reconciles': 'non-pair reconciled observation uncertainty',
    'observation-engine-clears-own': 'UNKNOWN projection reopened',
    'observation-engine-takeover-ignored': 'pair cleared subsequent engine uncertainty',
    'observation-restart-clears-own': 'restart confirmation cleared observation reconciliation fence',
    'publication-fence-overwrite': 'publication overwrote sticky fence',
    'observation-clears-engine-unknown': 'observation acknowledged engine uncertainty',
    'publication-clears-engine-unknown': 'observation acknowledged engine uncertainty',
    'publication-pre-cas-epoch': 'fenced final response committed or published',
    'publication-post-cas-epoch': 'fenced CAS enabled publication',
    'initial-lateness': 'initial read outside scheduling window admitted',
    'initial-cooldown': 'initial read outside scheduling window admitted',
    'current-age-ceiling': 'invalid native age admitted or closure repeated',
    'current-age-future': 'invalid native age admitted or closure repeated',
    'containment-callback-under-lock': 'containment callback ran under account lock',
    'late-cas-publishes': 'late CAS exposed publication',
    'late-single-cas': 'late single CAS acknowledged or reopened use',
    'late-publication-reopens': 'late publication reopened use or floor',
    'future-periodic-two-layer': 'periodic failure did not close without publication',
}
for case in cases:
    name = case['name']
    if name.startswith('deadline-before-'):
        expected_failures[name] = 'expired pre-CAS deadline changed durable join'
    elif name.startswith('deadline-after-'):
        expected_failures[name] = 'late CAS acknowledged'
    elif name.startswith('recovery-'):
        expected_failures[name] = 'semantic join mismatch admitted or wrong refusal'
    elif name.startswith('response-') or name == 'future-observation':
        expected_failures[name] = 'invalid response join admitted'
if arguments.only:
    unknown = set(arguments.only) - {case['name'] for case in cases}
    if unknown:
        parser.error('unknown mutant selection')
    cases = [case for case in cases if case['name'] in arguments.only]

sources = sorted({edit['source'] for case in cases for edit in case['edits']})
tests = sorted(str(path.relative_to(repository)) for path in (repository/'internal/labv0').glob('*_test.go'))
identity = {name: hashlib.sha256((repository/name).read_bytes()).hexdigest() for name in sources+tests+['go.mod','go.sum']}
(output/'source-identity.json').write_text(json.dumps(identity,indent=2)+'\n')

def execute(command, name):
    logfile = output/(name+'.log')
    with logfile.open('w') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        (output/(name+'.pid')).write_text(str(process.pid)+'\n')
        code = process.wait()
    (output/(name+'.exit')).write_text(str(code)+'\n')
    return code, logfile.read_text(), str(logfile)

base_names = sorted({case['test'].split('$')[0].lstrip('^') for case in cases})
control_pattern = '^('+'|'.join(re.escape(name) for name in base_names)+')$'
command = ['/usr/bin/go','test','-tags=broker_lab','-p=1','-count=1','-timeout=5m','-v','-run='+control_pattern,'./internal/labv0']
code, text, logfile = execute(command, 'control')
control = dict(command=command, exit=code, log=logfile)
(output/'control.json').write_text(json.dumps(control,indent=2)+'\n')
if code != 0 or any('--- PASS: '+name+' (' not in text for name in base_names):
    raise SystemExit('unmutated control failed or a named test did not run')
results = []
for case in cases:
    command = ['/usr/bin/go','test','-tags=broker_lab','-p=1','-count=1','-timeout=3m','-v','-overlay='+case['overlay'],'-run='+case['test'],'./internal/labv0']
    code, text, logfile = execute(command, case['name'])
    base_name = case['test'].split('$')[0].lstrip('^')
    intended = code == 1 and '--- FAIL: '+base_name in text and expected_failures[case['name']] in text and '[build failed]' not in text and 'panic:' not in text
    results.append(dict(case, command=command, exit=code, intended_failure=intended, expected_failure=expected_failures[case['name']], log=logfile))
    (output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(case['name'], code, 'named assertion failure' if intended else 'SURVIVOR OR INVALID PLANT', flush=True)
if not all(row['intended_failure'] for row in results):
    raise SystemExit(1)
