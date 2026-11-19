#!/usr/bin/env python3
"""Bounded runner ownership and read-only exact-ID release joins, including failure."""
import importlib.util
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('program_cleanup', Path(__file__).parent.parent / 'cleanup-programs.py')
program_cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(program_cleanup)


def ownership(text):
    maps, programs = [], []
    malformed = False
    for line in text.splitlines():
        if not line.startswith(('MAP_ID', 'PROGRAM_ID')):
            continue
        match = re.fullmatch(r'(MAP_ID|PROGRAM_ID) ([1-9][0-9]{0,9}) ([A-Za-z0-9_]+)', line)
        if not match or int(match[2]) > 4294967295:
            malformed = True
            continue
        target = maps if match[1] == 'MAP_ID' else programs
        if match[2] in target:
            malformed = True
        else:
            target.append(match[2])
    complete = (not malformed and len(maps) == 12 and len(programs) == 1
                and text.splitlines().count('OWNERSHIP_COMPLETE 12 1') == 1)
    return maps, complete


def map_absent(status, stdout, stderr, ident):
    # Validated using strace syscall injection (ENOENT), without a BPF syscall.
    # C-locale bpftool 7.7.0: map spelling differs from prog's "get by id".
    return (status == 255 and stdout == ''
            and stderr == f'Error: get map by id ({ident}): No such file or directory\n')


def join_maps(out, ids, timeout=10.0, interval=0.05, bpftool='bpftool'):
    deadline = time.monotonic() + timeout
    pending = list(ids)
    with (out / 'map-cleanup.log').open('a') as log:
        while pending:
            for ident in pending[:]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    print('MAP_RELEASE_TIMEOUT', *pending, file=log, flush=True)
                    return 1
                with (out / f'map-{ident}-after.stdout').open('a+') as stdout, \
                        (out / f'map-{ident}-after.stderr').open('a+') as stderr:
                    stdout.write(f'QUERY_ID {ident}\n'); stdout.flush(); start_out = stdout.tell()
                    stderr.write(f'QUERY_ID {ident}\n'); stderr.flush(); start_err = stderr.tell()
                    try:
                        result = subprocess.run([bpftool, 'map', 'show', 'id', ident],
                                                env=dict(os.environ, LC_ALL='C'),
                                                stdout=stdout, stderr=stderr,
                                                timeout=remaining, check=False)
                    except (OSError, subprocess.TimeoutExpired) as error:
                        print('MAP_ABSENCE_UNPROVEN', ident, repr(error), file=log, flush=True)
                        return 1
                    stdout.seek(start_out); output = stdout.read()
                    stderr.seek(start_err); error = stderr.read()
                print('MAP_QUERY_STATUS', ident, result.returncode, file=log, flush=True)
                if time.monotonic() >= deadline:
                    return 1
                if map_absent(result.returncode, output, error, ident):
                    print('MAP_ABSENT', ident, file=log, flush=True)
                    pending.remove(ident)
                elif result.returncode != 0:
                    print('MAP_ABSENCE_UNPROVEN', ident, file=log, flush=True)
                    return 1
            if pending:
                time.sleep(min(interval, max(0, deadline - time.monotonic())))
    return 0


def stop(process, grace):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=grace)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass  # No absence inference; external joins still fail if IDs survive.


def supervise(command, out, timeout=180.0, grace=5.0, cleanup_timeout=10.0, bpftool='bpftool'):
    """Caller owns a new output directory. No successful cleanup masks failure."""
    process = None
    status = 125
    interrupted = [0]
    previous = {}

    def handle(signum, _frame):
        interrupted[0] = signum
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, handle)
    try:
        with (out / 'runner.log').open('w') as stdout, (out / 'verifier.stderr').open('w') as stderr:
            try:
                process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if interrupted[0] or time.monotonic() >= deadline:
                        status = 128 + interrupted[0] if interrupted[0] else 124
                        stop(process, grace)
                        break
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
                else:
                    status = process.returncode if process.returncode >= 0 else 128 - process.returncode
                if interrupted[0]:
                    status = 128 + interrupted[0]
            except (OSError, subprocess.TimeoutExpired) as error:
                print('SUPERVISOR_FAILURE', repr(error), file=stderr, flush=True)
                status = 125
            finally:
                if process is not None:
                    stop(process, grace)
    finally:
        # Every runner outcome reaches these read-only joins, including partial load.
        (out / 'runner-status').write_text(f'{status}\n')
        text = (out / 'runner.log').read_text() if (out / 'runner.log').exists() else ''
        maps, complete = ownership(text)
        statuses = []
        for label, join in [('program', lambda: program_cleanup.join(out, timeout=cleanup_timeout, bpftool=bpftool)),
                            ('map', lambda: join_maps(out, maps, timeout=cleanup_timeout, bpftool=bpftool))]:
            try:
                statuses.append(join())
            except Exception as error:
                (out / (label+'-cleanup-exception.txt')).write_text(repr(error)+'\n')
                statuses.append(1)
        cleanup_status = int(bool(any(statuses) or not complete))
        (out / 'ownership-status').write_text('complete\n' if complete else 'incomplete: partial-load/unrecorded IDs absence UNPROVEN\n')
        (out / 'cleanup-status').write_text(f'{cleanup_status}\n')
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    result = status if status else cleanup_status
    (out / 'status').write_text(f'{result}\n')
    return result


if __name__ == '__main__':
    sys.exit(supervise([sys.argv[1], sys.argv[2]], Path(sys.argv[3])))
