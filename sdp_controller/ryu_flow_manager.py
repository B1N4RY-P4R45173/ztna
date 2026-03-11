#!/usr/bin/env python3
"""
Ryu Flow Manager
----------------
Called by spa_server.py to dynamically install/remove flows on S4
via Ryu's built-in ofctl REST API.

Ryu must be started with ofctl_rest:
  ryu-manager sdp_ryu_app.py ryu.app.ofctl_rest

Security: Ryu REST (port 8080) is protected by iptables on the host,
allowing only sdp_ctrl (10.0.0.2) to reach it:
  iptables -I INPUT -p tcp --dport 8080 ! -s 10.0.0.2 -j DROP

S4 datapath ID: 4 (decimal) = 0x0000000000000004
"""

import json
import logging
import urllib.request
import urllib.error
import subprocess
import os

# S4 switch datapath ID (decimal)
S4_DPID = 4

# Match constants
ETH_TYPE_IP  = 0x0800
IP_PROTO_TCP = 6

IP_GATEWAY  = '10.0.0.3'
IP_RESOURCE = '10.0.0.4'
PORT_SSH    = 22

PRIORITY_POLICY = 200


def _ryu_request(ryu_host, ryu_port, method, path, body=None):
    """
    Send a request to Ryu's REST API.
    
    Since spa_server.py runs inside a Mininet network namespace and Ryu
    listens on the host, we use 'nsenter' to escape to the host network
    namespace and make the HTTP request from there using curl.
    This avoids the need for any routing between the Mininet namespace
    and the host loopback.
    """
    url = f"http://{ryu_host}:{ryu_port}{path}"
    body_str = json.dumps(body) if body else '{}'

    # Find the host network namespace PID (pid 1 is always in host netns)
    cmd = [
        'nsenter', '--net=/proc/1/ns/net',
        'curl', '-s', '-X', method,
        '-H', 'Content-Type: application/json',
        '-d', body_str,
        '--connect-timeout', '5',
        url
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if result.returncode != 0:
            logging.error(f"Ryu REST curl failed: {result.stderr.strip()} → {url}")
            return None
        response_text = result.stdout.strip()
        if not response_text:
            # Ryu returns empty body on success for some endpoints
            return {}
        return json.loads(response_text)
    except subprocess.TimeoutExpired:
        logging.error(f"Ryu REST timeout → {url}")
        return None
    except json.JSONDecodeError:
        # Empty or non-JSON response still means success for flow add/delete
        return {}
    except Exception as e:
        logging.error(f"Ryu REST error: {e}")
        return None


def install_s4_flow(ryu_host='127.0.0.1', ryu_port=8080, session_timeout=300):
    """
    Install gateway↔resource TCP 22 flows on S4 via Ryu REST API.
    hard_timeout ensures OVS auto-removes if controller crashes.
    Returns True on success.
    """
    flows = [
        # gateway → resource TCP 22
        {
            "dpid":         S4_DPID,
            "priority":     PRIORITY_POLICY,
            "hard_timeout": session_timeout,
            "idle_timeout": 0,
            "match": {
                "eth_type":  ETH_TYPE_IP,
                "ip_proto":  IP_PROTO_TCP,
                "ipv4_src":  IP_GATEWAY,
                "ipv4_dst":  IP_RESOURCE,
                "tcp_dst":   PORT_SSH
            },
            "actions": [{"type": "OUTPUT", "port": "NORMAL"}]
        },
        # resource → gateway TCP 22 return
        {
            "dpid":         S4_DPID,
            "priority":     PRIORITY_POLICY,
            "hard_timeout": session_timeout,
            "idle_timeout": 0,
            "match": {
                "eth_type":  ETH_TYPE_IP,
                "ip_proto":  IP_PROTO_TCP,
                "ipv4_src":  IP_RESOURCE,
                "ipv4_dst":  IP_GATEWAY,
                "tcp_src":   PORT_SSH
            },
            "actions": [{"type": "OUTPUT", "port": "NORMAL"}]
        }
    ]

    success = True
    for flow in flows:
        result = _ryu_request(ryu_host, ryu_port, 'POST',
                              '/stats/flowentry/add', flow)
        if result is None:
            success = False

    if success:
        logging.info(
            f"✓ S4 flows installed via Ryu REST "
            f"(gateway↔resource TCP 22, timeout={session_timeout}s)"
        )
    else:
        logging.error("✗ Failed to install one or more S4 flows via Ryu REST")

    return success


def remove_s4_flow(ryu_host='127.0.0.1', ryu_port=8080):
    """
    Delete gateway↔resource TCP 22 flows from S4 via Ryu REST API.
    Returns True on success.
    """
    flows = [
        # gateway → resource TCP 22
        {
            "dpid":     S4_DPID,
            "priority": PRIORITY_POLICY,
            "match": {
                "eth_type": ETH_TYPE_IP,
                "ip_proto": IP_PROTO_TCP,
                "ipv4_src": IP_GATEWAY,
                "ipv4_dst": IP_RESOURCE,
                "tcp_dst":  PORT_SSH
            }
        },
        # resource → gateway TCP 22 return
        {
            "dpid":     S4_DPID,
            "priority": PRIORITY_POLICY,
            "match": {
                "eth_type": ETH_TYPE_IP,
                "ip_proto": IP_PROTO_TCP,
                "ipv4_src": IP_RESOURCE,
                "ipv4_dst": IP_GATEWAY,
                "tcp_src":  PORT_SSH
            }
        }
    ]

    success = True
    for flow in flows:
        result = _ryu_request(ryu_host, ryu_port, 'POST',
                              '/stats/flowentry/delete_strict', flow)
        if result is None:
            success = False

    if success:
        logging.info("✓ S4 flows removed via Ryu REST (gateway↔resource blocked)")
    else:
        logging.error("✗ Failed to remove one or more S4 flows via Ryu REST")

    return success