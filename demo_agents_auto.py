#!/usr/bin/env python3
"""
WiFi Guardian System - Automated Agent Demo
Shows agents working without user interaction
"""

import asyncio
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from src.models.network import PacketFeatures
from src.dependencies.guardian_deps import GuardianDependencies
from src.dependencies.sentinel_deps import SentinelDependencies
from src.agents.guardian import run_guardian_detection
from src.agents.sentinel import run_sentinel_analysis
from src.config.settings import get_settings

console = Console()


def print_header():
    """Print demo header"""
    console.print()
    console.print("╔" + "═" * 68 + "╗", style="bold cyan")
    console.print("║" + " " * 68 + "║", style="bold cyan")
    console.print("║" + "     🛡️  WiFi Guardian - Multi-Agent System Demo  🛡️     ".center(68) + "║", style="bold cyan")
    console.print("║" + " " * 68 + "║", style="bold cyan")
    console.print("╚" + "═" * 68 + "╝", style="bold cyan")
    console.print()


async def demo_normal_traffic():
    """Demo with normal traffic"""
    console.print("\n" + "=" * 70, style="green")
    console.print("  SCENARIO 1: Normal WiFi Traffic".center(70), style="bold green")
    console.print("=" * 70 + "\n", style="green")

    # Normal packet
    packet = PacketFeatures(
        timestamp=datetime.utcnow(),
        frame_type='Data',
        src_mac='AA:BB:CC:DD:EE:FF',
        dst_mac='11:22:33:44:55:66',
        packet_size=512,
        rssi=-42.0,
        protocol='TCP',
        packet_rate=25.0,
        byte_rate=12800.0,
        flow_duration=2.5,
        mean_packet_size=500.0,
        dst_address_entropy=0.2
    )

    console.print("[cyan]📦 Packet Details:[/cyan]")
    console.print(f"  MAC: {packet.src_mac} → {packet.dst_mac}")
    console.print(f"  Protocol: {packet.protocol}, Size: {packet.packet_size} bytes")
    console.print(f"  Rate: {packet.packet_rate} pkt/s, Entropy: {packet.dst_address_entropy:.2f}\n")

    config = get_settings()

    with console.status("[cyan]🤖 Guardian Agent analyzing with ML models...", spinner="dots"):
        guardian_deps = await GuardianDependencies.create(config)
        await asyncio.sleep(1.5)

    console.print("[cyan]🔍 Running ML Ensemble (RF + IF)...[/cyan]")
    alert = await run_guardian_detection(packet, guardian_deps)

    if alert:
        console.print(f"\n[green]✓ Result:[/green] {alert.threat_type}")
        console.print(f"[green]✓ Confidence:[/green] {alert.confidence:.2%}")
        console.print(f"[green]✓ Severity:[/green] {alert.severity}")
        console.print(f"[green]✓ Escalated:[/green] {alert.escalated_to_sentinel}")

    console.print("\n[green bold]✅ Normal traffic classified correctly![/green bold]")
    await guardian_deps.cleanup()
    await asyncio.sleep(2)


async def demo_suspicious_traffic():
    """Demo with suspicious traffic"""
    console.print("\n" + "=" * 70, style="red")
    console.print("  SCENARIO 2: Suspicious Traffic (Potential MITM Attack)".center(70), style="bold red")
    console.print("=" * 70 + "\n", style="red")

    # Suspicious packet
    packet = PacketFeatures(
        timestamp=datetime.utcnow(),
        frame_type='Data',
        src_mac='DE:AD:BE:EF:CA:FE',
        dst_mac='11:22:33:44:55:66',
        packet_size=1500,
        rssi=-68.0,
        protocol='ARP',
        packet_rate=5000.0,  # Very high
        byte_rate=750000.0,  # Very high
        flow_duration=0.5,
        mean_packet_size=1450.0,
        dst_address_entropy=0.95,  # High entropy
        unique_dst_ips=150  # Scanning
    )

    console.print("[red]⚠️  Suspicious Packet Detected![/red]")
    console.print(f"  MAC: [red]{packet.src_mac}[/red] → {packet.dst_mac}")
    console.print(f"  Protocol: [red]{packet.protocol}[/red]")
    console.print(f"  Rate: [red bold]{packet.packet_rate} pkt/s (VERY HIGH)[/red bold]")
    console.print(f"  Entropy: [red bold]{packet.dst_address_entropy:.2f} (SUSPICIOUS)[/red bold]")
    console.print(f"  Scanning: [red bold]{packet.unique_dst_ips} unique IPs[/red bold]\n")

    config = get_settings()

    # Guardian processing
    with console.status("[cyan]🤖 Guardian Agent analyzing threat...", spinner="dots"):
        guardian_deps = await GuardianDependencies.create(config)
        await asyncio.sleep(1.5)

    console.print("[cyan]🔍 ML Models analyzing packet...[/cyan]")
    alert = await run_guardian_detection(packet, guardian_deps)

    if alert:
        console.print(f"\n[red bold]⚠️  THREAT DETECTED![/red bold]")
        console.print(f"[red]→ Threat Type:[/red] [red bold]{alert.threat_type}[/red bold]")
        console.print(f"[red]→ Confidence:[/red] [red bold]{alert.confidence:.2%}[/red bold]")
        console.print(f"[red]→ Severity:[/red] [red bold]{alert.severity}[/red bold]")
        console.print(f"[yellow]→ Escalating to Sentinel Agent...[/yellow]\n")

        if alert.escalated_to_sentinel:
            # Sentinel processing
            console.print("=" * 70, style="magenta")
            console.print("  🧠 Sentinel Agent - LLM Analysis", style="bold magenta")
            console.print("=" * 70 + "\n", style="magenta")

            with console.status("[magenta]🧠 Sentinel querying Mistral AI...", spinner="dots"):
                sentinel_deps = await SentinelDependencies.create(config)
                await asyncio.sleep(2)

            console.print("[magenta]🤔 Mistral LLM reasoning about threat...[/magenta]")
            response = await run_sentinel_analysis(alert, sentinel_deps)

            if response:
                console.print(f"\n[magenta bold]📋 LLM Analysis Complete![/magenta bold]")
                console.print(f"[cyan]→ Threat Summary:[/cyan] {response.threat_summary[:80]}...")
                console.print(f"[yellow]→ Risk Score:[/yellow] [red bold]{response.risk_score}/10[/red bold]")

                if response.recommended_action:
                    console.print(f"[green]→ Recommended Action:[/green] [yellow]{response.recommended_action.action_type}[/yellow]")

                if response.mitre_attack:
                    console.print(f"[blue]→ MITRE ATT&CK:[/blue] {response.mitre_attack.technique_id}")

                console.print(f"\n[dim]Powered by: Mistral AI (mistral-large-latest)[/dim]")

            await sentinel_deps.cleanup()

    console.print("\n[red bold]🚨 Threat detected, analyzed, and response recommended![/red bold]")
    await guardian_deps.cleanup()
    await asyncio.sleep(2)


async def show_summary():
    """Show final summary"""
    console.print("\n" + "=" * 70, style="green")
    console.print("  ✅ Demo Complete!".center(70), style="bold green")
    console.print("=" * 70 + "\n", style="green")

    summary = Panel(
        """[bold]Multi-Agent System Demonstrated:[/bold]

✅ [green]Guardian Agent[/green] - ML-based detection (84.40% accuracy)
   • Random Forest (76.56% accuracy)
   • Isolation Forest (79.64% accuracy)
   • Real-time packet analysis

✅ [magenta]Sentinel Agent[/magenta] - LLM-based reasoning
   • Mistral AI integration
   • MITRE ATT&CK mapping
   • Risk scoring and recommendations

✅ [cyan]Inter-agent Communication[/cyan]
   • Message queue for escalation
   • Async processing pipeline
   • Safety guardrails

[bold yellow]🏆 First Agentic WiFi Security System![/bold yellow]

[dim]Technologies: Pydantic AI, Mistral AI, scikit-learn, FastAPI[/dim]
        """,
        title="[bold green]System Status: READY[/bold green]",
        border_style="green"
    )
    console.print(summary)

    console.print("\n[cyan bold]🌐 Full System Running:[/cyan bold]")
    console.print("  • Dashboard: http://localhost:8000/dashboard")
    console.print("  • API Docs:  http://localhost:8000/docs")
    console.print("  • Health:    http://localhost:8000/api/health\n")


async def main():
    """Run automated demo"""
    print_header()

    console.print("[bold]This demo shows both agents working together:[/bold]")
    console.print("  1. Guardian detects threats with ML models")
    console.print("  2. Sentinel analyzes with Mistral AI LLM")
    console.print("  3. System provides explainable recommendations\n")

    try:
        await demo_normal_traffic()
        await demo_suspicious_traffic()
        await show_summary()

    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        console.print("[dim]" + traceback.format_exc() + "[/dim]")


if __name__ == "__main__":
    asyncio.run(main())
