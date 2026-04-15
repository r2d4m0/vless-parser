from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import argparse
import html
import os
import re

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_PATH = REPO_ROOT / "githubmirror" / "whitelist-vless.txt"
DEFAULT_RELIABLE_OUTPUT_PATH = REPO_ROOT / "githubmirror" / "ru-sni-best-vless.txt"
GITHUB_AUTH_HOSTS = {"github.com", "raw.githubusercontent.com", "api.github.com"}
REPO_URL = "https://github.com/r2d4m0/vless-parser"

WHITELIST_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://white-lists.vercel.app/api/filter?code=RU",
    "https://wlrus.lol/confs/selected.txt",
]

RU_SNI_DOMAINS = {
    "2gis.com",
    "2gis.ru",
    "api.avito.ru",
    "api-maps.yandex.ru",
    "avito.ru",
    "avito.st",
    "dzen.ru",
    "gosuslugi.ru",
    "hh.ru",
    "kinopoisk.ru",
    "mail.ru",
    "max.ru",
    "m.vk.ru",
    "ok.ru",
    "ozon.ru",
    "ozone.ru",
    "pikabu.ru",
    "pochta.ru",
    "rbc.ru",
    "rzd.ru",
    "rutube.ru",
    "sberbank.ru",
    "sun6-20.userapi.com",
    "sun6-21.userapi.com",
    "sun6-22.userapi.com",
    "sun9-101.userapi.com",
    "sun9-38.userapi.com",
    "tbank.ru",
    "vk.com",
    "vk.ru",
    "wb.ru",
    "wildberries.ru",
    "ya.ru",
    "yandex.com",
    "yandex.net",
    "yandex.ru",
}

ALLOWED_PROTOCOL = "vless"
ALLOWED_SECURITY = {"reality", "tls"}
URI_PATTERN = re.compile(r"(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://")
INSECURE_PATTERN = re.compile(
    r"(?:[?&;]|3%[Bb])(allowinsecure|allow_insecure|insecure)=(?:1|true|yes)(?:[&;#]|$|(?=\s|$))",
    re.IGNORECASE,
)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/143.0.0.0 Safari/537.36"
)
PREFERRED_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 9443}
RELIABLE_TRANSPORT_SCORES = {
    "tcp": 14,
    "xhttp": 12,
    "grpc": 10,
    "ws": 7,
}
PREFERRED_FINGERPRINTS = {"chrome", "firefox", "edge", "safari"}
AVOID_FINGERPRINTS = {"qq", "random", "randomized"}
RELIABLE_SCORE_THRESHOLD = 60


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        os.environ[key] = value.strip().strip('"').strip("'")


load_dotenv(REPO_ROOT / ".env")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()


@dataclass(frozen=True)
class GeneratorSettings:
    output_path: Path
    reliable_output_path: Path
    timeout: int
    max_attempts: int
    max_workers: int
    reliable_limit: int


@dataclass(frozen=True)
class NormalizedConfig:
    raw_uri: str
    dedupe_key: tuple[str, ...]
    source_index: int
    source_url: str
    host: str
    port: int
    security: str
    transport: str
    sni: str
    host_header: str
    fingerprint: str
    public_key: str
    short_id: str
    path: str
    mode: str
    packet_encoding: str


@dataclass
class SourceResult:
    index: int
    url: str
    configs: list[NormalizedConfig]
    stats: Counter
    error: str | None = None


@dataclass(frozen=True)
class OutputSummary:
    path: Path
    changed: bool
    old_count: int
    new_count: int
    added_count: int
    removed_count: int


@dataclass(frozen=True)
class OutputProfile:
    label: str
    path: Path
    title: str
    description: str


def build_session(max_pool_size: int) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=max_pool_size,
        pool_maxsize=max_pool_size,
        max_retries=Retry(
            total=1,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "HEAD", "OPTIONS"),
        ),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def build_request_headers(url: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    host = (urlsplit(url).hostname or "").casefold()
    if GITHUB_TOKEN and host in GITHUB_AUTH_HOSTS:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def fetch_text(url: str, session: requests.Session, timeout: int, max_attempts: int) -> str:
    last_error: Exception = RuntimeError("No attempts made")
    for _ in range(max_attempts):
        try:
            response = session.get(
                url,
                timeout=timeout,
                headers=build_request_headers(url),
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as exc:
            last_error = exc
    raise last_error


def format_fetch_error(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "Connect timeout"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "Read timeout"
    if isinstance(exc, requests.exceptions.Timeout):
        return "Timeout"
    if isinstance(exc, requests.exceptions.HTTPError):
        try:
            return f"HTTP {exc.response.status_code}"
        except Exception:
            return "HTTP error"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Connection error"
    return str(exc)


def split_subscription_lines(data: str) -> list[str]:
    prepared = URI_PATTERN.sub(lambda match: f"\n{match.group(0)}", data)
    return [
        line.strip()
        for line in prepared.splitlines()
        if line.strip() and not line.startswith("#")
    ]


def is_insecure_uri(uri: str) -> bool:
    decoded = unquote(html.unescape(uri.strip()))
    return bool(INSECURE_PATTERN.search(decoded))


def normalize_domain(value: str | None) -> str:
    if not value:
        return ""
    normalized = unquote(value).strip().strip(".").casefold()
    if not normalized:
        return ""
    if normalized.startswith("[") and "]" in normalized:
        normalized = normalized[1:normalized.index("]")]
    if "," in normalized:
        normalized = normalized.split(",", 1)[0].strip()
    host_candidate, sep, maybe_port = normalized.rpartition(":")
    if sep and host_candidate and maybe_port.isdigit():
        normalized = host_candidate
    return normalized


def get_host_kind(host: str) -> str:
    try:
        parsed_ip = ip_address(host)
    except ValueError:
        return "hostname"
    return "ipv6" if parsed_ip.version == 6 else "ipv4"


def matches_domain(value: str, domains: set[str]) -> bool:
    normalized = normalize_domain(value)
    if not normalized:
        return False
    if normalized in domains:
        return True
    parts = normalized.split(".")
    for index in range(1, len(parts)):
        if ".".join(parts[index:]) in domains:
            return True
    return False


def is_russian_sni(config: NormalizedConfig) -> bool:
    return matches_domain(config.sni, RU_SNI_DOMAINS) or matches_domain(config.host_header, RU_SNI_DOMAINS)


def parse_vless_uri(
    uri: str,
    source_index: int,
    source_url: str,
) -> tuple[NormalizedConfig | None, str | None]:
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return None, "invalid_url"

    if parsed.scheme.casefold() != ALLOWED_PROTOCOL:
        return None, "non_vless"

    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None, "invalid_hostport"

    if not parsed.username or not host or not port:
        return None, "missing_core_fields"

    params = {
        key.casefold(): value.strip()
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    }
    security = params.get("security", "").casefold()
    if security not in ALLOWED_SECURITY:
        return None, "bad_security"

    sni = normalize_domain(params.get("sni"))
    host_header = normalize_domain(params.get("host"))
    if not sni and not host_header:
        return None, "missing_sni_host"

    transport = (params.get("type") or "tcp").casefold()
    dedupe_key = (
        host.casefold(),
        str(port),
        security,
        transport,
        sni,
        host_header,
        params.get("pbk", ""),
        params.get("sid", ""),
        params.get("path", ""),
        (params.get("mode") or "").casefold(),
        (params.get("packetingencoding") or params.get("packetencoding") or "").casefold(),
        unquote(parsed.username).strip(),
    )
    return (
        NormalizedConfig(
            raw_uri=uri.strip(),
            dedupe_key=dedupe_key,
            source_index=source_index,
            source_url=source_url,
            host=host,
            port=port,
            security=security,
            transport=transport,
            sni=sni,
            host_header=host_header,
            fingerprint=(params.get("fp") or "").casefold(),
            public_key=params.get("pbk", ""),
            short_id=params.get("sid", ""),
            path=params.get("path", ""),
            mode=(params.get("mode") or "").casefold(),
            packet_encoding=(params.get("packetingencoding") or params.get("packetencoding") or "").casefold(),
        ),
        None,
    )


def process_source(
    index: int,
    url: str,
    settings: GeneratorSettings,
    session: requests.Session,
) -> SourceResult:
    stats: Counter = Counter()
    configs: list[NormalizedConfig] = []

    try:
        raw_text = fetch_text(
            url=url,
            session=session,
            timeout=settings.timeout,
            max_attempts=settings.max_attempts,
        )
    except Exception as exc:
        return SourceResult(
            index=index,
            url=url,
            configs=[],
            stats=stats,
            error=format_fetch_error(exc),
        )

    stats["sources_ok"] += 1

    for line in split_subscription_lines(raw_text):
        if is_insecure_uri(line):
            stats["insecure_removed"] += 1
            continue

        normalized, reject_reason = parse_vless_uri(line, source_index=index, source_url=url)
        if normalized is None:
            stats[reject_reason or "rejected"] += 1
            continue

        configs.append(normalized)

    stats["accepted"] += len(configs)
    return SourceResult(index=index, url=url, configs=configs, stats=stats)


def merge_configs(results: list[SourceResult]) -> tuple[list[NormalizedConfig], Counter]:
    merged_stats: Counter = Counter()
    seen: set[tuple[str, ...]] = set()
    merged: list[NormalizedConfig] = []

    for result in sorted(results, key=lambda item: item.index):
        merged_stats.update(result.stats)
        for config in result.configs:
            if config.dedupe_key in seen:
                merged_stats["duplicates"] += 1
                continue
            seen.add(config.dedupe_key)
            merged.append(config)

    return merged, merged_stats


def sort_base_configs(configs: list[NormalizedConfig]) -> list[NormalizedConfig]:
    return sorted(
        configs,
        key=lambda config: (
            not is_russian_sni(config),
            config.security != "reality",
            config.sni or config.host_header or config.host,
            config.host,
            config.port,
            config.transport,
            config.raw_uri,
        ),
    )


def source_bonus(url: str) -> int:
    lowered = url.casefold()
    if "igareck" in lowered or "wlrus.lol" in lowered:
        return 6
    if "white-lists.vercel.app" in lowered:
        return 5
    if "byewhitelists" in lowered:
        return 4
    if "zieng2" in lowered:
        return 3
    return 0


def reliable_score(config: NormalizedConfig) -> int:
    score = 0
    score += 24 if is_russian_sni(config) else -100
    score += 24 if config.security == "reality" else 8
    score += RELIABLE_TRANSPORT_SCORES.get(config.transport, -6)
    score += 12 if config.public_key else -20
    score += 4 if config.short_id else 0
    score += 6 if config.port in PREFERRED_PORTS else 0
    score += 4 if config.fingerprint in PREFERRED_FINGERPRINTS else 0
    score -= 8 if config.fingerprint in AVOID_FINGERPRINTS else 0
    score += 2 if config.path and config.transport in {"ws", "grpc", "xhttp"} else 0
    score += 2 if get_host_kind(config.host) == "hostname" else 0
    score -= 10 if get_host_kind(config.host) == "ipv6" else 0
    score += source_bonus(config.source_url)
    return score


def build_reliable_configs(
    configs: list[NormalizedConfig],
    limit: int,
) -> tuple[list[NormalizedConfig], Counter]:
    stats: Counter = Counter()
    best_by_server: dict[tuple[str, int, str], tuple[int, NormalizedConfig]] = {}

    for config in configs:
        if not is_russian_sni(config):
            stats["reliable_non_ru_sni"] += 1
            continue
        if config.security != "reality":
            stats["reliable_non_reality"] += 1
            continue
        if config.transport not in RELIABLE_TRANSPORT_SCORES:
            stats["reliable_bad_transport"] += 1
            continue
        if not config.public_key:
            stats["reliable_missing_pbk"] += 1
            continue
        if get_host_kind(config.host) == "ipv6":
            stats["reliable_ipv6_removed"] += 1
            continue
        if config.fingerprint in AVOID_FINGERPRINTS:
            stats["reliable_bad_fp"] += 1
            continue

        score = reliable_score(config)
        if score < RELIABLE_SCORE_THRESHOLD:
            stats["reliable_low_score"] += 1
            continue

        server_key = (
            config.host.casefold(),
            config.port,
            config.sni or config.host_header,
        )
        previous = best_by_server.get(server_key)
        if previous is not None and previous[0] >= score:
            stats["reliable_server_duplicates"] += 1
            continue
        if previous is not None:
            stats["reliable_server_replaced"] += 1
        best_by_server[server_key] = (score, config)

    selected = sorted(
        best_by_server.values(),
        key=lambda item: (
            -item[0],
            item[1].sni or item[1].host_header or item[1].host,
            item[1].host,
            item[1].port,
            item[1].raw_uri,
        ),
    )
    if limit > 0:
        selected = selected[:limit]

    stats["reliable_selected"] = len(selected)
    return [config for _, config in selected], stats


def compare_output(path: Path, lines: list[str]) -> OutputSummary:
    old_lines = read_config_lines(path) if path.exists() else []
    new_lines = [line for line in lines if line.strip()]
    old_set = set(old_lines)
    new_set = set(new_lines)
    return OutputSummary(
        path=path,
        changed=old_lines != new_lines,
        old_count=len(old_lines),
        new_count=len(new_lines),
        added_count=len(new_set - old_set),
        removed_count=len(old_set - new_set),
    )


def read_config_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def build_metadata_lines(profile: OutputProfile, config_count: int) -> list[str]:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return [
        f"# profile-title: {profile.title}",
        "# profile-update-interval: 9",
        f"# profile-web-page-url: {REPO_URL}",
        f"# profile-desc: {profile.description}; Parsed by VLESS Parser; Updated: {generated_at}",
        f"# profile-count: {config_count}",
        "",
    ]


def render_output_text(profile: OutputProfile, lines: list[str]) -> str:
    config_lines = [line for line in lines if line.strip()]
    metadata_lines = build_metadata_lines(profile, len(config_lines))
    body = metadata_lines + config_lines
    return "\n".join(body) + ("\n" if body else "")


def has_expected_metadata(path: Path, profile: OutputProfile) -> bool:
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    expected_title = f"# profile-title: {profile.title}"
    expected_url = f"# profile-web-page-url: {REPO_URL}"
    expected_desc_fragment = f"# profile-desc: {profile.description}; Parsed by VLESS Parser;"
    return (
        len(lines) >= 4
        and lines[0] == expected_title
        and lines[2] == expected_url
        and lines[3].startswith(expected_desc_fragment)
    )


def write_output(profile: OutputProfile, lines: list[str]) -> OutputSummary:
    summary = compare_output(profile.path, lines)
    metadata_ok = has_expected_metadata(profile.path, profile)
    if summary.changed or not metadata_ok:
        profile.path.parent.mkdir(parents=True, exist_ok=True)
        profile.path.write_text(render_output_text(profile, lines), encoding="utf-8")
        summary = OutputSummary(
            path=summary.path,
            changed=True,
            old_count=summary.old_count,
            new_count=summary.new_count,
            added_count=summary.added_count,
            removed_count=summary.removed_count,
        )
    return summary


def print_output_summary(label: str, summary: OutputSummary) -> None:
    print(f"[INFO] {label}_output={summary.path.as_posix()}")
    print(f"[INFO] {label}_changed={'yes' if summary.changed else 'no'}")
    print(f"[INFO] {label}_old_count={summary.old_count}")
    print(f"[INFO] {label}_new_count={summary.new_count}")
    print(f"[INFO] {label}_added={summary.added_count}")
    print(f"[INFO] {label}_removed={summary.removed_count}")


def load_configs_from_file(path: Path) -> list[NormalizedConfig]:
    configs: list[NormalizedConfig] = []
    if not path.exists():
        return configs

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or is_insecure_uri(stripped):
            continue
        normalized, _ = parse_vless_uri(stripped, source_index=0, source_url="local-file")
        if normalized is not None:
            configs.append(normalized)
    return configs


def run(settings: GeneratorSettings) -> int:
    base_profile = OutputProfile(
        label="base",
        path=settings.output_path,
        title="VLESS Parser | Whitelist",
        description="Whitelist VLESS configs",
    )
    reliable_profile = OutputProfile(
        label="reliable",
        path=settings.reliable_output_path,
        title="VLESS Parser | RU SNI Best",
        description="RU-SNI shortlist",
    )

    session = build_session(max_pool_size=max(settings.max_workers, len(WHITELIST_SOURCES)))
    results: list[SourceResult] = []

    with ThreadPoolExecutor(max_workers=settings.max_workers) as executor:
        futures = [
            executor.submit(process_source, index, url, settings, session)
            for index, url in enumerate(WHITELIST_SOURCES, start=1)
        ]
        for future in as_completed(futures):
            results.append(future.result())

    failed_results = [result for result in results if result.error]
    for result in sorted(failed_results, key=lambda item: item.index):
        print(f"[WARN] {result.url} -> {result.error}")

    successful_results = [result for result in results if not result.error]
    if not successful_results:
        print("[ERROR] No whitelist sources were fetched successfully. Existing output files were left untouched.")
        return 1

    base_configs, stats = merge_configs(successful_results)
    if not base_configs and settings.output_path.exists():
        print("[ERROR] Filtering produced an empty whitelist set. Existing output files were left untouched.")
        return 1

    sorted_base_configs = sort_base_configs(base_configs)
    reliable_configs, reliable_stats = build_reliable_configs(sorted_base_configs, settings.reliable_limit)
    stats.update(reliable_stats)

    if not reliable_configs and settings.reliable_output_path.exists():
        print("[WARN] Reliable RU-SNI filter produced an empty set. Existing reliable output file was left untouched.")

    base_summary = write_output(
        base_profile,
        [config.raw_uri for config in sorted_base_configs],
    )
    print_output_summary("base", base_summary)

    if reliable_configs:
        reliable_summary = write_output(
            reliable_profile,
            [config.raw_uri for config in reliable_configs],
        )
        print_output_summary("reliable", reliable_summary)
    else:
        reliable_summary = compare_output(settings.reliable_output_path, [])
        print_output_summary("reliable", reliable_summary)

    print(f"[INFO] merged_total={len(sorted_base_configs)}")
    print(f"[INFO] reliable_total={len(reliable_configs)}")
    for key in sorted(stats):
        print(f"[INFO] {key}={stats[key]}")
    return 0


def parse_args() -> GeneratorSettings:
    parser = argparse.ArgumentParser(
        description="Generate sorted whitelist VLESS configs plus a stricter RU-SNI shortlist."
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help="Output file path. Default: githubmirror/whitelist-vless.txt",
    )
    parser.add_argument(
        "--reliable-output",
        default=str(DEFAULT_RELIABLE_OUTPUT_PATH),
        help="Output file path for stricter RU-SNI configs. Default: githubmirror/ru-sni-best-vless.txt",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("WHITELIST_TIMEOUT", "8")),
        help="Per-request timeout in seconds.",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=int(os.environ.get("WHITELIST_MAX_ATTEMPTS", "2")),
        help="Maximum fetch attempts per source.",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=min(8, len(WHITELIST_SOURCES)),
        help="Number of parallel fetch workers.",
    )
    parser.add_argument(
        "--reliable-limit",
        type=int,
        default=int(os.environ.get("RELIABLE_CFG_LIMIT", "200")),
        help="Maximum number of configs in ru-sni-best-vless.txt",
    )
    args = parser.parse_args()
    return GeneratorSettings(
        output_path=Path(args.output).resolve(),
        reliable_output_path=Path(args.reliable_output).resolve(),
        timeout=args.timeout,
        max_attempts=args.max_attempts,
        max_workers=max(1, args.max_workers),
        reliable_limit=max(1, args.reliable_limit),
    )


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
