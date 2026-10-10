"""Simulated log generator for GuardLog."""
import argparse
import os
import random
from datetime import datetime, timedelta

DAY_SECONDS = 24 * 60 * 60

USERS = ["admin", "root", "alice", "bob", "carol", "dave", "eve", "guest", "test", "user1"]
COMMON_PASSWORDS = ["123456", "password", "qwerty", "admin123", "letmein",
                    "welcome1", "iloveyou", "abc123", "111111", "dragon"]
NORMAL_PATHS = ["/home", "/profile", "/search?q=notes", "/about", "/dashboard", "/settings"]
SCAN_PATHS = ["/admin", "/phpmyadmin", "/.env", "/wp-login.php", "/backup.zip",
              "/config", "/server-status", "/.git/config", "/api/v1/users", "/console"]
SIGNATURES = ["../../etc/passwd", "UNION SELECT", "<script>alert(1)</script>",
              "' OR '1'='1", "cmd.exe", "/bin/sh"]
ATTACK_KINDS = ["brute_force", "credential_stuffing", "scan", "signature"]


def random_ip(rng):
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def fmt(ts, ip, user, action, pw, path):
    # path is the LAST field on purpose: it may contain spaces (e.g. "UNION SELECT")
    return f"{ts.strftime('%Y-%m-%dT%H:%M:%S')} ip={ip} user={user} action={action} pw={pw} path={path}"


def generate_logs(n_lines=10000, seed=42, attack_ratio=0.15):
    """Return a list of log lines sorted by time. Same seed = same logs."""
    rng = random.Random(seed)
    start = datetime(2026, 10, 11, 0, 0, 0)
    normal_ips = [random_ip(rng) for _ in range(200)]
    attacker_ips = [random_ip(rng) for _ in range(12)]

    n_attack = int(n_lines * attack_ratio)
    n_normal = n_lines - n_attack
    events = []  # list of (timestamp, line)

    # 1) Normal traffic
    for _ in range(n_normal):
        ts = start + timedelta(seconds=rng.randint(0, DAY_SECONDS))
        ip = rng.choice(normal_ips)
        user = rng.choice(USERS)
        roll = rng.random()
        if roll < 0.55:
            events.append((ts, fmt(ts, ip, user, "REQUEST", "-", rng.choice(NORMAL_PATHS))))
        elif roll < 0.92:
            events.append((ts, fmt(ts, ip, user, "LOGIN_OK", "-", "/login")))
        else:
            typo = "pw" + str(rng.randint(100, 999))
            events.append((ts, fmt(ts, ip, user, "LOGIN_FAIL", typo, "/login")))

    # 2) Attack bursts
    remaining = n_attack
    while remaining > 0:
        kind = rng.choice(ATTACK_KINDS)
        length = min(remaining, rng.randint(30, 120))
        ip = rng.choice(attacker_ips)
        t = start + timedelta(seconds=rng.randint(0, DAY_SECONDS - 300))
        target_user = rng.choice(["admin", "root"])
        for _ in range(length):
            t += timedelta(seconds=rng.uniform(0.2, 2.0))
            if kind == "brute_force":      # one IP, one user, many passwords
                line = fmt(t, ip, target_user, "LOGIN_FAIL", rng.choice(COMMON_PASSWORDS), "/login")
            elif kind == "credential_stuffing":  # one IP, many users
                line = fmt(t, ip, rng.choice(USERS), "LOGIN_FAIL", rng.choice(COMMON_PASSWORDS), "/login")
            elif kind == "scan":           # one IP, many paths
                line = fmt(t, ip, "-", "REQUEST_404", "-", rng.choice(SCAN_PATHS))
            else:                          # signature attack payloads
                payload = rng.choice(SIGNATURES)
                line = fmt(t, ip, "-", "REQUEST", "-", "/search?q=" + payload)
            events.append((t, line))
        remaining -= length

    events.sort(key=lambda e: e[0])
    return [line for _, line in events]


def write_logs(out_path, n_lines=10000, seed=42):
    folder = os.path.dirname(out_path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    lines = generate_logs(n_lines, seed)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate simulated auth/server logs")
    ap.add_argument("--lines", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/sample.log")
    args = ap.parse_args()
    n = write_logs(args.out, args.lines, args.seed)
    print(f"Wrote {n} lines to {args.out}")