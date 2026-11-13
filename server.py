"""lab-tools: 로컬 실습 대상(127.0.0.1) 전용 정찰 도구 MCP 서버"""
import functools
import inspect
import ipaddress
import json
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("lab-tools")

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
MAX_BODY = 4000  # 에이전트에게 돌려줄 본문 최대 길이(바이트)
AUDIT_LOG = Path(__file__).resolve().parent / "logs" / "audit.jsonl"  # 실행 위치와 무관하게 고정
_audit_lock = threading.Lock()  # 동시 호출에서 줄이 섞이지 않게 한다


def _loopback_only(target: str) -> str:
    """IP 형식이 아니거나 루프백이 아니면 거부한다."""
    ip = ipaddress.ip_address(target)  # "-oN x" 같은 옵션 끼워넣기는 여기서 ValueError
    if not ip.is_loopback:
        raise ValueError(f"허용 범위 밖 대상: {target}")
    return str(ip)


def _check_ports(ports: str) -> str:
    """'80', '1-1000', '22,80,3000' 같은 형식이고 1~65535 안인지 확인한다."""
    for part in ports.split(","):
        if not re.fullmatch(r"[0-9]+(-[0-9]+)?", part):  # \d 대신 [0-9]: 아스키 숫자만
            raise ValueError(f"잘못된 포트 지정: {part!r}")
        lo, _, hi = part.partition("-")
        if not 1 <= int(lo) <= int(hi or lo) <= 65535:
            raise ValueError(f"포트 범위 밖: {part!r}")
    return ports


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """리다이렉트를 따라가지 않는다. 외부 주소로 튕겨 나가는 것을 막기 위해서다."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _write_audit(record: dict) -> None:
    """감사 기록 한 줄을 덧붙인다. 실패해도 도구 호출을 막지 않고 stderr에만 알린다(fail-open)."""
    try:
        line = json.dumps(record, ensure_ascii=False, default=repr) + "\n"
        with _audit_lock:
            AUDIT_LOG.parent.mkdir(exist_ok=True)
            with AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(line)
    except Exception as err:  # stdout은 MCP 통신에 쓰이므로 반드시 stderr로 보낸다
        print(f"[audit] 기록 실패: {type(err).__name__}: {err}", file=sys.stderr)


def _audited(func):
    """도구 호출을 허용/거부/오류와 함께 logs/audit.jsonl에 한 줄씩 남긴다."""
    signature = inspect.signature(func)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            call_args = dict(bound.arguments)
        except TypeError:  # 인자 개수가 안 맞는 호출도 받은 그대로 남긴다
            call_args = {"args": list(args), "kwargs": kwargs}
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "tool": func.__name__,
            "args": call_args,
        }
        start = time.monotonic()
        try:
            result = func(*args, **kwargs)
        except ValueError as err:  # 검사 코드가 거부한 호출
            record.update(outcome="denied", error=str(err))
            raise
        except Exception as err:  # 검사는 통과했지만 실행 중 실패
            record.update(outcome="error", error=f"{type(err).__name__}: {err}")
            raise
        else:
            record.update(outcome="allowed", response_bytes=len(result.encode("utf-8")))
            return result
        finally:
            record["duration_ms"] = round((time.monotonic() - start) * 1000)
            _write_audit(record)

    return wrapper


@mcp.tool()
@_audited
def port_scan(target: str, ports: str = "1-10000") -> str:
    """루프백 주소(127.0.0.1)의 열린 포트와 서비스 버전을 nmap으로 스캔한다.
    ports 예: "1-10000", "80,443,3000"."""
    ip = _loopback_only(target)
    ports = _check_ports(ports)
    result = subprocess.run(
        ["nmap", "-sV", "-p", ports, ip],  
        capture_output=True, text=True, timeout=600,
    )
    return result.stdout or result.stderr


@mcp.tool()
@_audited
def http_get(url: str) -> str:
    """localhost 웹 서비스에 GET 요청을 한 번 보내고 상태 코드, 응답 헤더, 본문 앞부분을 돌려준다.
    리다이렉트는 따라가지 않고 Location 헤더로만 보여준다."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("http, https만 허용")
    if "@" in parts.netloc or parts.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"허용 범위 밖 URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Claude_MCP_Agent"})
    try:
        resp = _opener.open(req, timeout=10)
    except urllib.error.HTTPError as err:  
        resp = err
    body = resp.read(MAX_BODY).decode("utf-8", errors="replace")
    headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return f"HTTP {resp.getcode()}\n{headers}\n\n{body}"


if __name__ == "__main__":
    mcp.run()  
