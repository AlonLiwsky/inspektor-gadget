#!/usr/bin/env python3
"""Join release of only runner-recorded program IDs; never delete programs."""
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def join(out, timeout=10.0, interval=0.05, bpftool='bpftool'):
    deadline = time.monotonic() + timeout
    with (out / 'cleanup.log').open('a') as log:
        def record(message):
            print(message, file=log, flush=True)

        pending = []
        for line in (out / 'runner.log').read_text().splitlines():
            fields = line.split()
            if not fields or fields[0] != 'PROGRAM_ID':
                continue
            if (len(fields) != 3 or not re.fullmatch(r'[1-9][0-9]{0,9}', fields[1])
                    or int(fields[1]) > 4294967295):
                record('PROGRAM_ID_INVALID ' + repr(line))
                return 1
            if fields[1] not in pending:
                pending.append(fields[1])
        env = dict(os.environ, LC_ALL='C')
        while pending:
            for ident in pending[:]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    record('PROGRAM_RELEASE_TIMEOUT ' + ' '.join(pending))
                    return 1
                # Regular files avoid inherited-output pipe hangs. Keep all attempts.
                with (out / f'program-{ident}-after.txt').open('a+') as evidence, \
                        (out / f'program-{ident}-after-stdout.txt').open('a+') as stdout:
                    evidence.write(f'QUERY_ID {ident}\n')
                    evidence.flush()
                    start = evidence.tell()
                    stdout.write(f'QUERY_ID {ident}\n')
                    stdout.flush()
                    stdout_start = stdout.tell()
                    try:
                        result = subprocess.run(
                            [bpftool, 'prog', 'show', 'id', ident], env=env,
                            stdout=stdout, stderr=evidence, timeout=remaining,
                            check=False)
                    except (OSError, subprocess.TimeoutExpired) as error:
                        record(f'PROGRAM_ABSENCE_UNPROVEN {ident} {error}')
                        return 1
                    evidence.seek(start)
                    output = evidence.read()
                    stdout.seek(stdout_start)
                    stdout_output = stdout.read()
                    record(f'PROGRAM_QUERY_STATUS {ident} {result.returncode}')
                    if time.monotonic() >= deadline:
                        record('PROGRAM_RELEASE_TIMEOUT ' + ' '.join(pending))
                        return 1
                    # Exact observed contract: owned-115-absence-classifier proof,
                    # bpftool v7.7.0/libbpf v1.7: 255, empty stdout, ENOENT stderr.
                    # A missing executable/file or permission error is NOT absence.
                    absent = f'Error: get by id ({ident}): No such file or directory\n'
                    if result.returncode == 255 and stdout_output == '' and output == absent:
                        record(f'PROGRAM_ABSENT {ident}')
                        pending.remove(ident)
                    elif result.returncode == 0:
                        record(f'PROGRAM_STILL_PRESENT {ident}')
                    else:
                        record(f'PROGRAM_ABSENCE_UNPROVEN {ident} status={result.returncode}')
                        return 1
            if pending:
                time.sleep(min(interval, max(0, deadline - time.monotonic())))
    return 0


if __name__ == '__main__':
    sys.exit(join(Path(sys.argv[1])))
