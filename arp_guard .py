#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARP 스푸핑 탐지 · 방어 실습 도구 (Ubuntu 전용, 추가 설치 불필요)
ARP spoofing detection & defense lab tool (Ubuntu only, nothing extra to install)

[원리]
  ARP 스푸핑 공격자는 "내가 공유기(게이트웨이)야"라고 거짓말을 해서
  내 PC의 ARP 표에 적힌 게이트웨이 MAC 주소를 자기 MAC 주소로 바꿔치기합니다.
  이 프로그램은 ARP 표를 몇 초마다 확인해서
    1) 게이트웨이의 MAC 주소가 바뀌었는지
    2) 게이트웨이와 똑같은 MAC 주소를 가진 다른 기기가 있는지
  를 감시하고, 이상이 있으면 경고합니다.

[How it works]
  An ARP spoofing attacker lies and says "I am the router (gateway)",
  replacing the gateway MAC address in this PC's ARP table with its own.
  This program checks the ARP table every few seconds to see whether
    1) the gateway's MAC address has changed
    2) another device has the same MAC address as the gateway
  and prints a warning when something is wrong.

[사용법]
  python3 arp_guard.py            감시(탐지)만 하기
  python3 arp_guard.py --demo     가짜 공격 상황으로 경고 화면 미리 보기
  sudo python3 arp_guard.py --pin 감시 + 게이트웨이 MAC 고정(방어)
  sudo python3 arp_guard.py --unpin  고정 해제(실습 끝난 뒤 원상복구)

[Usage]
  python3 arp_guard.py            Watch (detect) only
  python3 arp_guard.py --demo     Preview the warning screen with a fake attack
  sudo python3 arp_guard.py --pin Watch + pin the gateway MAC (defense)
  sudo python3 arp_guard.py --unpin  Remove the pin (restore after the lab)
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime

# 몇 초마다 검사할지
# How often to check, in seconds
CHECK_INTERVAL = 3

# 경고 기록이 저장되는 파일
# File where warnings are saved
LOG_FILE = "arp_guard.log"

# IP 주소 모양(예: 192.168.0.1)과 MAC 주소 모양(예: aa:bb:cc:dd:ee:ff)을 찾는 규칙
# Patterns that match an IP address (e.g. 192.168.0.1) and a MAC address (e.g. aa:bb:cc:dd:ee:ff)
IP_PATTERN = r"\d{1,3}(?:\.\d{1,3}){3}"
MAC_PATTERN = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"


# ───────────────────────── 기본 도구 ─────────────────────────
# ───────────────────────── Basic helpers ─────────────────────

def run(command):
    """리눅스 명령을 실행하고 출력 글자를 돌려줍니다. 실패하면 빈 문자열.
    Run a Linux command and return its output text. Empty string on failure."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def log(message, alert=False):
    """화면에 출력하고, 경고(alert)는 파일에도 남깁니다.
    Print to the screen; warnings (alert) are also written to the log file."""
    line = f"[{datetime.now():%H:%M:%S}] {message}"
    print(line, flush=True)
    if alert:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now():%Y-%m-%d} {line}\n")
        except OSError:
            # 기록 파일을 못 써도(권한 문제 등) 감시는 계속합니다.
            # Keep watching even if the log file cannot be written (e.g. permissions).
            pass


# ───────────────────────── 네트워크 정보 읽기 ─────────────────────────
# ───────────────────────── Reading network info ───────────────────────

def parse_gateway(route_text):
    """'ip route' 출력에서 (게이트웨이 IP, 네트워크 장치 이름)을 찾습니다.
    예: default via 192.168.52.2 dev ens33 proto dhcp ...

    Find (gateway IP, network device name) in the output of 'ip route'.
    Example: default via 192.168.52.2 dev ens33 proto dhcp ..."""
    match = re.search(rf"default via ({IP_PATTERN}) dev (\S+)", route_text)
    return (match.group(1), match.group(2)) if match else (None, None)


def parse_arp_table(neigh_text):
    """'ip neigh' 출력을 {IP: MAC} 사전으로 바꿉니다.
    예: 192.168.52.2 dev ens33 lladdr 00:50:56:aa:bb:cc REACHABLE

    Turn the output of 'ip neigh' into an {IP: MAC} dictionary.
    Example: 192.168.52.2 dev ens33 lladdr 00:50:56:aa:bb:cc REACHABLE"""
    table = {}
    for line in neigh_text.splitlines():
        match = re.match(rf"({IP_PATTERN}) .*lladdr ({MAC_PATTERN})", line)
        if match:
            table[match.group(1)] = match.group(2).lower()
    return table


def get_gateway():
    """현재 PC의 게이트웨이 IP와 장치 이름을 읽어 옵니다.
    Read this PC's gateway IP and device name."""
    return parse_gateway(run(["ip", "route", "show", "default"]))


def get_arp_table():
    """현재 PC의 ARP 표를 읽어 옵니다.
    Read this PC's current ARP table."""
    return parse_arp_table(run(["ip", "-4", "neigh", "show"]))


# ───────────────────────── 탐지 로직 ─────────────────────────
# ───────────────────────── Detection logic ───────────────────

def check(table, gateway_ip, trusted_mac):
    """ARP 표를 검사해서 문제점 목록(문장들)을 돌려줍니다. 비어 있으면 정상.
    Check the ARP table and return a list of problems (sentences). Empty means OK."""
    problems = []
    current_mac = table.get(gateway_ip)

    # 검사 1: 게이트웨이 MAC이 처음 기억한 값과 달라졌는가?
    # Check 1: Is the gateway MAC different from the value remembered at start?
    if current_mac and current_mac != trusted_mac:
        problems.append(
            f"게이트웨이({gateway_ip}) MAC 주소가 바뀜: "
            f"{trusted_mac} → {current_mac}  ← 공격자 MAC으로 의심")

    # 검사 2: 게이트웨이와 같은 MAC을 쓰는 다른 IP가 있는가?
    #         (공격자 PC의 실제 IP를 알려주는 단서)
    # Check 2: Does any other IP use the same MAC as the gateway?
    #          (A clue to the attacker PC's real IP)
    if current_mac:
        for ip, mac in table.items():
            if ip != gateway_ip and mac == current_mac:
                problems.append(
                    f"{ip} 가 게이트웨이와 같은 MAC({mac})을 사용 중 "
                    f"← 이 IP가 공격자일 가능성 높음")
    return problems


# ───────────────────────── 방어(고정/해제) ─────────────────────────
# ───────────────────────── Defense (pin / unpin) ───────────────────

def pin(gateway_ip, mac, device):
    """게이트웨이 MAC을 '영구(permanent)'로 고정합니다.
    고정되면 가짜 ARP 응답이 와도 ARP 표가 바뀌지 않습니다.

    Pin the gateway MAC as 'permanent'.
    Once pinned, fake ARP replies can no longer change the ARP table."""
    result = subprocess.run(
        ["ip", "neigh", "replace", gateway_ip, "lladdr", mac,
         "dev", device, "nud", "permanent"])
    return result.returncode == 0


def unpin(gateway_ip, device):
    """고정을 풀어 원래(자동) 상태로 되돌립니다.
    Remove the pin and go back to the original (automatic) state."""
    result = subprocess.run(["ip", "neigh", "del", gateway_ip, "dev", device])
    return result.returncode == 0


def need_root():
    """관리자 권한(sudo)으로 실행했는지 확인하고, 아니면 종료합니다.
    Make sure the program was started with admin rights (sudo); exit if not."""
    if os.geteuid() != 0:
        sys.exit("이 기능은 관리자 권한이 필요합니다. 명령 앞에 sudo 를 붙여 다시 실행하세요.")


# ───────────────────────── 실행 모드 ─────────────────────────
# ───────────────────────── Run modes ─────────────────────────

def watch(use_pin):
    """ARP 표를 계속 감시합니다. use_pin이 참이면 먼저 MAC을 고정합니다.
    Keep watching the ARP table. If use_pin is true, pin the MAC first."""
    gateway_ip, device = get_gateway()
    if not gateway_ip:
        sys.exit("게이트웨이를 찾지 못했습니다. 네트워크 연결(ip route)을 확인하세요.")

    # ARP 표에 게이트웨이가 아직 없을 수 있으므로 ping 한 번으로 채워 넣습니다.
    # The gateway may not be in the ARP table yet, so one ping fills it in.
    run(["ping", "-c", "1", "-W", "1", gateway_ip])
    first_table = get_arp_table()
    trusted_mac = first_table.get(gateway_ip)
    if not trusted_mac:
        sys.exit(f"게이트웨이({gateway_ip})의 MAC 주소를 읽지 못했습니다.")

    # 시작할 때 이미 공격받는 중이면 '가짜 MAC'을 정상값으로 기억하게 됩니다.
    # 게이트웨이와 같은 MAC을 쓰는 기기가 벌써 있다면 그런 상황이므로 멈춥니다.
    # If an attack is already running at start, the 'fake MAC' would be remembered as normal.
    # If some device already shares the gateway's MAC, that is the case, so stop here.
    suspects = [ip for ip, mac in first_table.items()
                if ip != gateway_ip and mac == trusted_mac]
    if suspects:
        sys.exit(f"⚠ 이미 공격받는 중일 수 있습니다: {', '.join(suspects)} 가 "
                 f"게이트웨이와 같은 MAC({trusted_mac})을 쓰고 있습니다.\n"
                 f"  공격을 먼저 중단하고 1분쯤 뒤에 다시 실행하세요.")

    print("=" * 62)
    print(" ARP 스푸핑 감시 시작  (종료: Ctrl + C)")
    print(f"  네트워크 장치 : {device}")
    print(f"  게이트웨이 IP : {gateway_ip}")
    print(f"  정상 MAC 주소 : {trusted_mac}   ← 이 값을 기준으로 기억합니다")
    print("  ※ 반드시 공격을 시작하기 '전'에 실행해야 기준값이 정확합니다.")
    print("=" * 62)

    if use_pin:
        if pin(gateway_ip, trusted_mac, device):
            log("방어 적용: 게이트웨이 MAC을 고정했습니다. (해제: --unpin)")
        else:
            log("고정 실패. 감시만 계속합니다.")

    # 지금 공격받는 중인지 기억하는 표시
    # Flag that remembers whether we are currently under attack
    under_attack = False
    try:
        while True:
            problems = check(get_arp_table(), gateway_ip, trusted_mac)
            if problems:
                for p in problems:
                    log("🚨 경고! " + p, alert=True)
                if not under_attack:
                    # 삐 소리를 내고 대응 방법을 한 번만 안내합니다.
                    # Beep and show the response guide only once.
                    print("\a", end="")
                    print("   → 대응: 중요한 로그인/결제를 멈추고,")
                    print(f"           sudo python3 {sys.argv[0]} --pin 으로 MAC을 고정하세요.")
                under_attack = True
            else:
                if under_attack:
                    log("✅ 정상으로 돌아왔습니다.", alert=True)
                else:
                    log(f"정상 (게이트웨이 {gateway_ip} = {trusted_mac})")
                under_attack = False
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        # Ctrl + C 를 누르면 여기로 와서 깔끔하게 종료합니다.
        # Pressing Ctrl + C lands here for a clean exit.
        print(f"\n감시를 종료합니다. 경고 기록은 {LOG_FILE} 에 저장되어 있습니다.")


def demo():
    """실제 공격 없이, 미리 만든 ARP 표로 경고가 어떻게 뜨는지 보여줍니다.
    Show how warnings look using prepared ARP tables, without a real attack."""
    gateway_ip, good, bad = "192.168.52.2", "00:50:56:aa:bb:cc", "00:0c:29:11:22:33"
    scenes = [
        ("평소 상태", {gateway_ip: good, "192.168.52.130": bad}),
        ("공격 시작(게이트웨이 MAC이 공격자 것으로 바뀜)",
         {gateway_ip: bad, "192.168.52.130": bad}),
        ("공격 종료", {gateway_ip: good, "192.168.52.130": bad}),
    ]
    print("[데모] 가짜 데이터로 탐지 과정을 보여줍니다.\n")
    for title, table in scenes:
        print(f"--- {title} ---")
        problems = check(table, gateway_ip, good)
        for p in problems:
            log("🚨 경고! " + p)
        if not problems:
            log(f"정상 (게이트웨이 {gateway_ip} = {good})")
        print()
        time.sleep(1)


def main():
    """입력한 옵션(--demo, --pin, --unpin)에 맞는 기능을 실행합니다.
    Run the feature that matches the given option (--demo, --pin, --unpin)."""
    parser = argparse.ArgumentParser(description="ARP 스푸핑 탐지·방어 실습 도구")
    parser.add_argument("--demo", action="store_true", help="가짜 공격 상황 미리 보기")
    parser.add_argument("--pin", action="store_true", help="게이트웨이 MAC 고정 후 감시 (sudo 필요)")
    parser.add_argument("--unpin", action="store_true", help="MAC 고정 해제 (sudo 필요)")
    args = parser.parse_args()

    if args.demo:
        demo()
    elif args.unpin:
        need_root()
        gateway_ip, device = get_gateway()
        ok = gateway_ip and unpin(gateway_ip, device)
        print("고정을 해제했습니다." if ok else "해제할 고정 항목이 없거나 실패했습니다.")
    else:
        if args.pin:
            need_root()
        watch(args.pin)


if __name__ == "__main__":
    main()
