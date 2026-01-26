#!/usr/bin/env python3
"""
Quick test script to verify the defense simulation endpoint
"""

import requests
import json
import time
from datetime import datetime


def test_simulation():
    """Test the real-time defense simulation"""
    print("=" * 60)
    print("WiFi Guardian - Defense Simulation Test")
    print("=" * 60)
    print()

    url = "http://localhost:8000/api/demo/defense-simulation"

    print(f"Connecting to: {url}")
    print("Starting 30-second simulation...")
    print()

    try:
        response = requests.get(url, stream=True, timeout=35)

        stats = {
            'total_packets': 0,
            'legitimate': 0,
            'threats_blocked': 0,
            'config': None
        }

        print("📡 LIVE PACKET FEED:")
        print("-" * 60)

        for line in response.iter_lines():
            if line:
                line_str = line.decode('utf-8')

                # SSE format: "data: {...}"
                if line_str.startswith('data: '):
                    data_str = line_str[6:]  # Remove "data: " prefix

                    try:
                        event = json.loads(data_str)
                        event_type = event.get('type')
                        data = event.get('data', {})

                        if event_type == 'config':
                            stats['config'] = data
                            print(f"⚙️  Configuration:")
                            print(f"   Duration: {data['total_duration']}s")
                            print(f"   Attack Window: {data['attack_start']}s - {data['attack_end']}s")
                            print(f"   Packets/sec: {data['packets_per_second']}")
                            print()

                        elif event_type == 'legitimate_packet':
                            stats['legitimate'] += 1
                            stats['total_packets'] = data['stats']['total_packets']

                            # Print every 10th packet to avoid spam
                            if stats['legitimate'] % 10 == 0:
                                print(f"✅ [{data['timestamp']:2d}s] Packet #{data['packet_id']:3d} ALLOWED "
                                      f"({data['src_mac']} → {data['dst_mac']}) "
                                      f"Checksum: {data.get('payload_checksum', 'N/A')[:8]}")

                        elif event_type == 'threat_blocked':
                            stats['threats_blocked'] += 1
                            stats['total_packets'] = data['stats']['total_packets']

                            print(f"🚫 [{data['timestamp']:2d}s] Packet #{data['packet_id']:3d} BLOCKED "
                                  f"| {data['threat_type']} ({data['confidence']}) "
                                  f"| Anomaly: {data['anomaly_score']}")
                            print(f"   ⚠️  Payload Status: {data['payload_status']}")
                            print(f"   Expected Checksum: {data['expected_checksum']}")
                            print(f"   Received Checksum: {data['received_checksum']} ❌")
                            print()

                        elif event_type == 'second_summary':
                            # Optional: show progress indicator
                            pass

                        elif event_type == 'simulation_complete':
                            print()
                            print("=" * 60)
                            print("🎯 SIMULATION COMPLETE")
                            print("=" * 60)
                            print()

                            final_stats = data['final_stats']
                            print(f"📊 Final Statistics:")
                            print(f"   Total Packets:        {final_stats['total_packets']}")
                            print(f"   Legitimate Packets:   {final_stats['legitimate_packets']} "
                                  f"(allowed)")
                            print(f"   Attack Packets:       {final_stats['attack_packets']}")
                            print(f"   Threats Detected:     {final_stats['threats_detected']}")
                            print(f"   Threats Blocked:      {final_stats['threats_blocked']}")
                            print(f"   Data Corrupted:       {final_stats['data_corrupted']} ✅")
                            print(f"   Integrity Checks:     {final_stats['data_integrity_checks']}")
                            print()
                            print(f"🛡️  Defense Effectiveness:  {data['defense_effectiveness']}")
                            print(f"✅ Data Integrity Rate:    {data['data_integrity_rate']}")
                            print()

                            if data['success']:
                                print("✅ SUCCESS: All threats blocked, zero data corruption!")
                            else:
                                print("⚠️  WARNING: Some threats may have been missed")

                            print()
                            break

                        elif event_type == 'error':
                            print(f"❌ Error: {data.get('error')}")
                            break

                    except json.JSONDecodeError:
                        print(f"Warning: Could not parse: {data_str}")

    except requests.exceptions.Timeout:
        print("❌ Connection timed out")
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to server")
        print("   Make sure the backend is running: python main.py")
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    test_simulation()
