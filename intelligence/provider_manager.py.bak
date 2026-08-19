"""Independent remote threat-intelligence fan-out."""
from concurrent.futures import ThreadPoolExecutor, wait
from intelligence.contracts import result, ERROR, TIMEOUT
from intelligence.diagnostics import load_and_report_provider_configuration, log_provider_result
from intelligence.openphish import lookup_url as openphish
from intelligence.urlhaus import lookup_url as urlhaus
from intelligence.urlscan import lookup_url as urlscan
from virustotal_scanner import lookup_url_virustotal

load_and_report_provider_configuration()


def collect_remote(url: str, timeout: float = 7.0) -> dict:
    jobs = {"virustotal": lookup_url_virustotal, "urlscan": urlscan, "urlhaus": urlhaus, "openphish": openphish}
    answers = {}
    pool = ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="intel")
    try:
        futures = {pool.submit(fn, url, timeout): name for name, fn in jobs.items()}
        done, pending = wait(futures, timeout=timeout + 0.5)
        for future in done:
            name = futures[future]
            try: answers[name] = future.result()
            except Exception as error: answers[name] = result(name, ERROR, reason=str(error))
            log_provider_result(name, url, answers[name])
        for future in pending:
            name = futures[future]
            future.cancel()
            answers[name] = result(name, TIMEOUT, reason=f"{name} exceeded the bounded provider timeout")
            log_provider_result(name, url, answers[name])
    finally:
        # Do not let a misbehaving adapter hold the canonical analysis open.
        pool.shutdown(wait=False, cancel_futures=True)
    return answers
