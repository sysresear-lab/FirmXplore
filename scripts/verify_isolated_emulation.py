"""Repeat operator-requested functional checks in fresh isolated guests."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task', action='append', required=True, type=Path,
                        help='Existing task containing canonical-rootfs.tar.gz and reports/analysis.json')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--repetitions', type=int, default=3, choices=range(1,4))
    args = parser.parse_args()
    if len(args.task) > 4:
        parser.error('at most four local firmware tasks are supported')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    work = output/'runs'
    repo = Path(__file__).resolve().parent.parent
    plans = []
    for sample, source in enumerate(args.task,1):
        source = source.resolve()
        archive = source/'canonical-rootfs.tar.gz'
        analysis = source/'reports/analysis.json'
        if not archive.is_file() or archive.stat().st_size > 64*1024*1024 or not analysis.is_file():
            raise ValueError('a bounded canonical archive and analysis.json are required')
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        for run in range(1,args.repetitions+1):
            name = f'sample{sample}-cold{run}'
            task = work/name
            (task/'reports').mkdir(parents=True)
            shutil.copyfile(archive, task/archive.name)
            shutil.copyfile(analysis, task/'reports/analysis.json')
            plans.append({'task_id':name,'sample':sample,'repetition':run,'source_task':str(source),
                          'input_sha256':digest,'task':task})
    plans.sort(key=lambda x:(x['repetition'],x['sample']))

    def execute(plan):
        started = time.monotonic()
        log = output/(plan['task_id']+'.log')
        command = [sys.executable,'-m','fwagent.cli','emulate',plan['task_id'],
                   '--workspace',str(work),'--backend','isolated-qemu','--timeout','300','--functional']
        try:
            with log.open('xb') as stream:
                process = subprocess.run(command,cwd=repo,stdout=stream,stderr=subprocess.STDOUT,timeout=330)
            result_path = plan['task']/'dynamic/isolated/result.json'
            result = json.loads(result_path.read_text(encoding='utf-8'))
            validation = result.get('functional_validation') or {}
            passed = (process.returncode == 0 and result.get('success') is True
                      and validation.get('functional_passed') is True and result.get('cleanup_succeeded') is True
                      and result.get('input_sha256') == plan['input_sha256'])
            return {k:v for k,v in plan.items() if k!='task'} | {
                'passed':passed,'cli_exit_code':process.returncode,
                'duration_seconds':round(time.monotonic()-started,3),
                'result_path':str(result_path.relative_to(output)),
                'worker_sha256':result.get('worker_sha256'),'http_probe_sha256':result.get('http_probe_sha256'),
                'image_id':result.get('image_id'),'functional_validation':validation,
                'cleanup_succeeded':result.get('cleanup_succeeded')}
        except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
            return {k:v for k,v in plan.items() if k!='task'} | {'passed':False,'error_type':type(exc).__name__}

    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(execute,plan) for plan in plans]
        for future in as_completed(pending):
            completed = future.result()
            outcomes.append(completed)
            outcomes.sort(key=lambda x:(x['sample'],x['repetition']))
            (output/'summary.json').write_text(json.dumps({'completed':len(outcomes),'scheduled':len(plans),'runs':outcomes},ensure_ascii=False,indent=2),encoding='utf-8')
            print(json.dumps({k:completed.get(k) for k in ['task_id','passed','duration_seconds']}),flush=True)
    identities = {(x.get('worker_sha256'),x.get('http_probe_sha256'),x.get('image_id')) for x in outcomes}
    success = len(outcomes)==len(plans) and all(x['passed'] for x in outcomes) and len(identities)==1
    summary = {'success':success,'completed':len(outcomes),'scheduled':len(plans),
               'independent_fresh_guests':True,'persistent_flash_state_validated':False,
               'same_worker_probe_image':len(identities)==1,'runs':outcomes}
    (output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
