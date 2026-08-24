"""Independent remote threat-intelligence fan-out (VirusTotal & OpenPhish)."""
from concurrent.futures import ThreadPoolExecutor, wait
from intelligence.contracts import result, ERROR, TIMEOUT
from intelligence.diagnostics import load_and_report_provider_configuration, log_provider_result
from intelligence.openphish import lookup_url as openphish
from virustotal_scanner import lookup_url_virustotal

load_and_report_provider_configuration()


def collect_remote(url: str, timeout: float = 6.0) -> dict:
    jobs = {"virustotal": lookup_url_virustotal, "openphish": openphish}
    answers = {}
    pool = ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="intel")
    try:
        futures = {pool.submit(fn, url, timeout): name for name, fn in jobs.items()}
        done, pending = wait(futures, timeout=timeout + 1.0)
        for future in done:
            name = futures[future]
            try:
                res = future.result()
                answers[name] = res if isinstance(res, dict) else result(name, ERROR, reason="Provider returned non-dict response")
            except Exception as error:
                answers[name] = result(name, ERROR, reason=str(error))
            log_provider_result(name, url, answers[name])
        for future in pending:
            name = futures[future]
            future.cancel()
            answers[name] = result(name, TIMEOUT, reason=f"{name} exceeded the bounded provider timeout")
            log_provider_result(name, url, answers[name])
    except Exception as exc:
        for name in jobs:
            if name not in answers:
                answers[name] = result(name, ERROR, reason=str(exc))
    finally:
        # Do not let a misbehaving adapter hold the canonical analysis open.
        pool.shutdown(wait=False, cancel_futures=True)

    for name in jobs:
        if name not in answers or not isinstance(answers[name], dict):
            answers[name] = result(name, ERROR, reason="Provider result missing")

    return answers
