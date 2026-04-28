#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlsplit


DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def ordered_unique(items: list[str]) -> list[str]:
    return list(OrderedDict.fromkeys(items))


def add_rule(target: list[str], rule: str | None) -> None:
    if rule:
        target.append(rule)


def extract_host(text: str) -> tuple[str | None, str]:
    host = text
    path = ""
    if "/" in text:
        host, path = text.split("/", 1)
        path = "/" + path
    host = host.strip(".")
    return (host or None), path


def wildcard_host_to_rule(host: str, prefer_suffix: bool) -> str | None:
    stripped = host.replace("*", "").strip(".")
    if not stripped:
        return None
    if DOMAIN_RE.fullmatch(stripped):
        rule_type = "DOMAIN-SUFFIX" if prefer_suffix else "DOMAIN"
        return f"{rule_type},{stripped}"

    keywords = [part for part in re.split(r"[^A-Za-z0-9-]+", stripped) if len(part) >= 4]
    if keywords:
        keywords.sort(key=len, reverse=True)
        return f"DOMAIN-KEYWORD,{keywords[0]}"
    return None


def host_to_rule(host: str, prefer_suffix: bool) -> str | None:
    if IP_RE.fullmatch(host):
        return f"IP-CIDR,{host}/32"
    if "*" in host:
        return wildcard_host_to_rule(host, prefer_suffix=prefer_suffix)
    if DOMAIN_RE.fullmatch(host):
        rule_type = "DOMAIN-SUFFIX" if prefer_suffix else "DOMAIN"
        return f"{rule_type},{host}"
    return None


def url_to_rule(url_text: str) -> str | None:
    candidate = url_text
    if "://" not in candidate:
        candidate = "http://" + candidate
    parsed = urlsplit(candidate)
    if not parsed.hostname:
        return None
    return host_to_rule(parsed.hostname, prefer_suffix=False)


def regex_to_rule(pattern: str) -> str | None:
    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 1:
        pattern = pattern[1:-1]
    elif pattern.startswith("/"):
        pattern = pattern[1:]
    return f"URL-REGEX,{pattern}" if pattern else None


def line_to_rule(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("!") or line.startswith("["):
        return None
    if line.startswith("/"):
        return regex_to_rule(line)
    if line.startswith("||"):
        host, _ = extract_host(line[2:])
        if not host:
            return None
        return host_to_rule(host, prefer_suffix=True)
    if line.startswith("|"):
        return url_to_rule(line[1:])
    if "://" in line:
        return url_to_rule(line)
    if "*" in line:
        return wildcard_host_to_rule(line, prefer_suffix=True)
    if DOMAIN_RE.fullmatch(line):
        return f"DOMAIN-SUFFIX,{line}"
    if IP_RE.fullmatch(line):
        return f"IP-CIDR,{line}/32"
    return None


def write_provider(path: Path, rules: list[str]) -> None:
    lines = ["payload:"] + [f"  - {rule}" for rule in rules]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_snippet(path: Path, provider_dir: str) -> None:
    content = f"""rule-providers:
  gfwlist-proxy:
    type: file
    behavior: classical
    path: ./{provider_dir}/gfwlist-proxy.yaml
    format: yaml

  gfwlist-direct:
    type: file
    behavior: classical
    path: ./{provider_dir}/gfwlist-direct.yaml
    format: yaml

rules:
  - RULE-SET,gfwlist-direct,DIRECT
  - RULE-SET,gfwlist-proxy,PROXY
"""
    path.write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert AutoProxy list.txt into Clash rule providers.")
    parser.add_argument("input", type=Path, nargs="?", default=Path("list.txt"))
    parser.add_argument("--output-dir", type=Path, default=Path("rule-providers"))
    args = parser.parse_args()

    proxy_rules: list[str] = []
    direct_rules: list[str] = []

    for raw_line in args.input.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        if line.startswith("@@"):
            add_rule(direct_rules, line_to_rule(line[2:]))
            continue
        add_rule(proxy_rules, line_to_rule(line))

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    proxy_rules = ordered_unique(proxy_rules)
    direct_rules = ordered_unique(direct_rules)

    write_provider(output_dir / "gfwlist-proxy.yaml", proxy_rules)
    write_provider(output_dir / "gfwlist-direct.yaml", direct_rules)
    write_snippet(output_dir / "rule-providers.yaml", output_dir.name)

    print(f"proxy rules: {len(proxy_rules)}")
    print(f"direct rules: {len(direct_rules)}")
    print(f"output dir: {output_dir}")


if __name__ == "__main__":
    main()
