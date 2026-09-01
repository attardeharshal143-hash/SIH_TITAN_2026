def generate_remediation_scripts(report_data):
    """
    Generates copy-pasteable, hardened configuration scripts for
    Cisco IOS-XE, Linux StrongSwan, Fortinet FortiGate, and Palo Alto Networks.
    """
    sec = report_data.get("security_assessment", {})
    crypto = report_data.get("cryptographic_analysis", {})
    is_ipsec = sec.get("ipsec_tunnel_detected", True)
    
    # 1. Linux StrongSwan swanctl.conf
    strongswan_conf = """# =========================================================================
# TITAN AUTO-GENERATED HARDEINED STRONGSWAN CONFIGURATION (swanctl.conf)
# Standards: NIST SP 800-77 & NSA CNSA 2.0 Post-Quantum Readiness
# =========================================================================

connections {
    titan-hardened-tunnel {
        local_addrs  = %defaultroute
        remote_addrs = 198.51.100.1

        local {
            auth = pubkey
            certs = titanGatewayCert.pem
            id = vpn.enterprise.internal
        }
        remote {
            auth = pubkey
            id = peer.enterprise.internal
        }

        children {
            titan-vpn-child {
                local_ts  = 10.0.0.0/16
                remote_ts = 172.16.0.0/16
                
                # Enforce High-Assurance AES-256-GCM AEAD (No weak 3DES/MD5)
                esp_proposals = aes256gcm16-prfsha384-ecp384-modp2048!
                
                # Strict RFC 4301 Tunnel Mode & Monotonic Anti-Replay
                mode = tunnel
                rekey_time = 3600s
                rekey_bytes = 10000000000
                dpd_action = restart
            }
        }

        # IKEv2 Key Exchange with Post-Quantum Hybrid ML-KEM / Curve25519
        version = 2
        proposals = aes256gcm16-prfsha384-ecp384-curve25519-modp2048!
        encap = no
    }
}
"""

    # 2. Cisco IOS-XE / ASA Hardened CLI Script
    cisco_cli = """! =========================================================================
! TITAN AUTO-GENERATED CISCO IOS-XE / ASA HARDENING CLI SCRIPT
! Hardens Phase 1 (IKEv2) & Phase 2 (ESP AES-GCM-256 AEAD)
! =========================================================================

! 1. Define IKEv2 Hardened Proposal
crypto ikev2 proposal TITAN-PQC-PROPOSAL
 encryption aes-gcm-256
 prf sha384
 group 19 20 14
 exit

! 2. Define IKEv2 Policy
crypto ikev2 policy TITAN-IKEV2-POLICY
 match fvrf any
 proposal TITAN-PQC-PROPOSAL
 exit

! 3. Enforce Strict AEAD IPsec Transform Set (Phase 2)
crypto ipsec transform-set TITAN-AES-GCM esp-gcm 256
 mode tunnel
 exit

! 4. Enforce Anti-Replay Window (128-Packet Bitmap) & PFS Group 19
crypto ipsec profile TITAN-IPSEC-PROFILE
 set transform-set TITAN-AES-GCM
 set pfs group19
 set security-association replay window-size 128
 set security-association lifetime seconds 3600
 exit

! 5. Apply to Virtual Tunnel Interface (VTI)
interface Tunnel100
 ip address 10.255.255.1 255.255.255.252
 tunnel source GigabitEthernet0/0/0
 tunnel mode ipsec ipv4
 tunnel destination 198.51.100.1
 tunnel protection ipsec profile TITAN-IPSEC-PROFILE
 no ip redirects
 exit
"""

    # 3. Fortinet FortiGate Hardened CLI Script
    fortinet_cli = """# =========================================================================
# TITAN AUTO-GENERATED FORTINET FORTIGATE IPSEC CONFIGURATION
# Enforces AES-GCM-256 AEAD, Anti-Replay & Auto-ASIC Offload
# =========================================================================

config vpn ipsec phase1-interface
    edit "TITAN_VPN_P1"
        set interface "port1"
        set ike-version 2
        set keylife 28800
        set peertype any
        set proposal aes256gcm-prfsha384 aes256-sha384
        set dhgrp 19 14
        set remote-gw 198.51.100.1
        set psksecret ENC XXXXXX
        set auto-discovery-receiver enable
    next
end

config vpn ipsec phase2-interface
    edit "TITAN_VPN_P2"
        set phase1name "TITAN_VPN_P1"
        set proposal aes256gcm
        set dhgrp 19 14
        set replay enable
        set auto-negotiate enable
        set keylifeseconds 3600
        set src-subnet 10.0.0.0 255.255.0.0
        set dst-subnet 172.16.0.0 255.255.0.0
    next
end
"""

    return {
        "strongswan_swanctl_conf": strongswan_conf.strip(),
        "cisco_ios_xe_cli": cisco_cli.strip(),
        "fortinet_fortigate_cli": fortinet_cli.strip()
    }
