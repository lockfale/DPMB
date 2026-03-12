"""Click CLI entry point and subcommands for dpmb (802.11DPMB)."""

import logging
import sys

import click

from ssid_monitor import __version__
from ssid_monitor.config import load_config
from ssid_monitor.db import get_connection, init_db

pass_config = click.make_pass_decorator(dict, ensure=True)


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config file (override)")
@click.option("--verbose", is_flag=True, help="Debug-level logging")
@click.version_option(version=__version__, prog_name="dpmb")
@click.pass_context
def cli(ctx, config_path, verbose):
    """Wireless SSID Beacon Monitor — passive 802.11 scanning with webhook alerts."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["verbose"] = verbose

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Load config if it exists (some commands like init don't need it)
    try:
        if config_path:
            ctx.obj["config"] = load_config(config_path)
        else:
            ctx.obj["config"] = load_config()
    except FileNotFoundError:
        ctx.obj["config"] = None


def _get_db(ctx):
    """Get a database connection from context, creating if needed."""
    if "db" not in ctx.obj or ctx.obj["db"] is None:
        config = ctx.obj.get("config")
        db_path = config.db_path if config else "/var/lib/dpmb/events.db"
        conn = get_connection(db_path)
        init_db(conn)
        ctx.obj["db"] = conn
    return ctx.obj["db"]


# --- Watchlist subcommand group ---

@cli.group()
def watch():
    """Manage the SSID watchlist."""
    pass


@watch.command("add")
@click.argument("ssid")
@click.pass_context
def watch_add(ctx, ssid):
    """Add an SSID to the watchlist."""
    from ssid_monitor.watchlist import add_ssid, SSIDAlreadyExists, SSIDTooLong

    db = _get_db(ctx)
    try:
        add_ssid(db, ssid)
        click.echo(f'Added "{ssid}" to watchlist.')
    except SSIDAlreadyExists:
        click.echo(f'Error: "{ssid}" already on watchlist.', err=True)
        ctx.exit(1)
    except SSIDTooLong:
        click.echo("Error: SSID exceeds 32-byte limit.", err=True)
        ctx.exit(1)


@watch.command("remove")
@click.argument("ssid")
@click.pass_context
def watch_remove(ctx, ssid):
    """Remove an SSID from the watchlist."""
    from ssid_monitor.watchlist import remove_ssid, SSIDNotFound

    db = _get_db(ctx)
    try:
        remove_ssid(db, ssid)
        click.echo(f'Removed "{ssid}" from watchlist.')
    except SSIDNotFound:
        click.echo(f'Error: "{ssid}" not found on watchlist.', err=True)
        ctx.exit(1)


@watch.command("list")
@click.pass_context
def watch_list(ctx):
    """List all watched SSIDs."""
    from ssid_monitor.watchlist import list_ssids

    db = _get_db(ctx)
    entries = list_ssids(db)
    if not entries:
        click.echo("No SSIDs on watchlist. Use 'dpmb watch add <SSID>' to add one.")
        return

    # Table header
    click.echo(f"{'SSID':<20} {'ACTIVE':<8} {'ADDED'}")
    for entry in entries:
        active = "yes" if entry["active"] else "no"
        click.echo(f"{entry['ssid']:<20} {active:<8} {entry['created_at']}")


@watch.command("disable")
@click.argument("ssid")
@click.pass_context
def watch_disable(ctx, ssid):
    """Temporarily stop monitoring an SSID without removing it."""
    from ssid_monitor.watchlist import disable_ssid, SSIDNotFound

    db = _get_db(ctx)
    try:
        disable_ssid(db, ssid)
        click.echo(f'Disabled "{ssid}".')
    except SSIDNotFound:
        click.echo(f'Error: "{ssid}" not found on watchlist.', err=True)
        ctx.exit(1)


@watch.command("enable")
@click.argument("ssid")
@click.pass_context
def watch_enable(ctx, ssid):
    """Re-enable a disabled SSID."""
    from ssid_monitor.watchlist import enable_ssid, SSIDNotFound

    db = _get_db(ctx)
    try:
        enable_ssid(db, ssid)
        click.echo(f'Enabled "{ssid}".')
    except SSIDNotFound:
        click.echo(f'Error: "{ssid}" not found on watchlist.', err=True)
        ctx.exit(1)


# --- Log subcommand group ---

@cli.group(name="log", invoke_without_command=True)
@click.option("--ssid", default=None, help="Filter by SSID name")
@click.option("--since", default=None, help="Events after datetime (ISO 8601 or relative: 24h, 7d)")
@click.option("--limit", "max_events", default=50, help="Max events to return (default 50)")
@click.pass_context
def log_group(ctx, ssid, since, max_events):
    """Query and export detection event log."""
    if ctx.invoked_subcommand is not None:
        return  # A subcommand like 'export' was called

    from ssid_monitor.logger import query_events

    db = _get_db(ctx)
    events = query_events(db, ssid=ssid, since=since, limit=max_events)

    if not events:
        click.echo("No detection events found.")
        return

    # Table header
    click.echo(f"{'TIME':<22} {'SSID':<18} {'RSSI':>5}  {'DEVICE MAC':<19} {'CH':>3}  {'ALERT'}")
    for e in events:
        alert = "yes" if e["alert_sent"] else "no (cooldown)"
        mac = e.get("device_mac") or "N/A"
        ch = e.get("channel") or "?"
        click.echo(
            f"{e['detected_at']:<22} {e['ssid']:<18} {e['rssi']:>5}  {mac:<19} {str(ch):>3}  {alert}"
        )


@log_group.command("export")
@click.option("--format", "fmt", type=click.Choice(["csv", "json"]), default="csv", help="Export format")
@click.option("--output", default=None, help="Output file path (default: stdout)")
@click.pass_context
def log_export(ctx, fmt, output):
    """Export full detection log."""
    from ssid_monitor.logger import export_events

    db = _get_db(ctx)
    data = export_events(db, fmt=fmt, output=output)

    if output:
        click.echo(f"Exported to {output}")
    else:
        click.echo(data)


# --- Standalone commands (stubs wired in later phases) ---

@cli.command()
@click.option("--auto", "auto_mode", is_flag=True, help="Non-interactive mode — use auto-detected defaults")
@click.pass_context
def init(ctx, auto_mode):
    """First-time setup — create config, database, and systemd service."""
    import socket
    from pathlib import Path

    click.echo("=== 802.11DPMB — First-Time Setup ===\n")

    # Auto-detect wireless interfaces
    from ssid_monitor.scanner import discover_wireless_interfaces
    found = discover_wireless_interfaces()
    if found:
        names = [i["name"] for i in found]
        click.echo(f"Detected wireless interfaces: {', '.join(names)}")
        default_iface = names[0]
    else:
        click.echo("No wireless interfaces detected (plug in adapter later).")
        default_iface = ""

    if auto_mode:
        wifi_interface = default_iface
        webhook_url = ""
        device_name = socket.gethostname()
        click.echo(f"Auto mode: interface={wifi_interface or '(auto-detect)'}, device={device_name}")
    else:
        wifi_interface = click.prompt("WiFi interface name (blank for auto-detect)", default=default_iface)
        webhook_url = click.prompt("Webhook URL for alerts (blank to skip)", default="")
        device_name = click.prompt("Device name", default=socket.gethostname())

    # Write config file
    config_dir = Path("/etc/dpmb")
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.toml"

    config_content = (
        "[dpmb]\n"
        f'device_id = "{device_name}"\n'
        f'wifi_interface = "{wifi_interface}"\n'
        "scan_interval_sec = 10\n"
        "cooldown_min = 60\n"
        f'webhook_url = "{webhook_url}"\n'
        "heartbeat_hour = 8\n"
        'log_level = "info"\n'
        'db_path = "/var/lib/dpmb/events.db"\n'
    )

    config_path.write_text(config_content)
    click.echo(f"\nConfig written to {config_path}")

    # Create database directory and initialize
    db_dir = Path("/var/lib/dpmb")
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = str(db_dir / "events.db")

    init_db(db_path)
    click.echo(f"Database initialized at {db_path}")

    click.echo("\nSetup complete. Next steps:")
    click.echo('  1. Add SSIDs to watch: dpmb watch add "TargetNetwork"')
    click.echo("  2. Start monitoring:   sudo systemctl start dpmb-scanner")
    click.echo("  3. Check status:       dpmb status")


@cli.command()
@click.pass_context
def start(ctx):
    """Start the monitoring daemon in the foreground."""
    import signal

    config = ctx.obj.get("config")
    if config is None:
        click.echo("Error: No config file found. Run 'dpmb init' first.", err=True)
        ctx.exit(2)

    # Auto-discover wireless interface if not configured
    from ssid_monitor.scanner import (
        setup_monitor_mode, restore_managed_mode, run_scan_loop,
        auto_select_interface, discover_wireless_interfaces,
    )

    interface = auto_select_interface(config.wifi_interface)
    if not interface:
        found = discover_wireless_interfaces()
        if not found:
            click.echo("Error: No wireless interfaces found. Plug in a WiFi adapter.", err=True)
        else:
            click.echo("Error: Could not select a wireless interface.", err=True)
        ctx.exit(2)

    # Update config so the rest of the pipeline uses the resolved interface
    config.wifi_interface = interface
    if interface != ctx.obj.get("_original_interface", interface):
        click.echo(f"Auto-detected wireless interface: {interface}")

    # Set up monitor mode
    try:
        setup_monitor_mode(interface)
    except RuntimeError as e:
        click.echo(f"Error: Failed to enable monitor mode on {interface}. {e}", err=True)
        ctx.exit(2)

    # Initialize database
    db = _get_db(ctx)
    init_db(db)

    # Notify systemd we're ready
    try:
        from systemd.daemon import notify  # type: ignore[import-untyped]
        notify("READY=1")
        notify(f"STATUS=Monitoring on {interface}")
    except ImportError:
        pass

    # Handle SIGTERM for graceful shutdown
    def handle_sigterm(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, handle_sigterm)

    click.echo(f"Monitoring started on {interface}. Press Ctrl+C to stop.")

    try:
        run_scan_loop(config, db)
    except KeyboardInterrupt:
        click.echo("\nShutting down...")
    finally:
        restore_managed_mode(interface)
        click.echo(f"Restored managed mode on {interface}.")


@cli.command()
@click.pass_context
def status(ctx):
    """Check if the monitoring service is running."""
    import subprocess as sp
    from datetime import datetime, timezone

    # Check systemd service status
    try:
        result = sp.run(
            ["systemctl", "is-active", "dpmb-scanner"],
            capture_output=True, text=True,
        )
        is_active = result.stdout.strip() == "active"
    except FileNotFoundError:
        is_active = False

    if not is_active:
        click.echo("Status: STOPPED")
        return

    config = ctx.obj.get("config")
    db = _get_db(ctx)

    # Gather stats
    watchlist_count = db.execute("SELECT COUNT(*) FROM watchlist WHERE active = 1").fetchone()[0]

    last_detection = db.execute(
        "SELECT ssid, detected_at, rssi FROM detection_events ORDER BY detected_at DESC LIMIT 1"
    ).fetchone()

    last_hb = db.execute(
        "SELECT triggered_at FROM alerts WHERE ssid = '__heartbeat__' ORDER BY triggered_at DESC LIMIT 1"
    ).fetchone()

    # Uptime from systemd
    try:
        result = sp.run(
            ["systemctl", "show", "dpmb-scanner", "--property=ActiveEnterTimestamp"],
            capture_output=True, text=True,
        )
        ts_str = result.stdout.strip().split("=", 1)[1] if "=" in result.stdout else ""
        if ts_str:
            # Parse systemd timestamp format
            now = datetime.now(timezone.utc)
            click.echo(f"Status: ACTIVE")
            click.echo(f"Interface: {config.wifi_interface if config else 'unknown'} (monitor mode)")
            click.echo(f"Watchlist: {watchlist_count} SSIDs")
        else:
            click.echo("Status: ACTIVE")
    except Exception:
        click.echo("Status: ACTIVE")

    if last_detection:
        click.echo(
            f"Last detection: {last_detection['detected_at']} "
            f"({last_detection['ssid']}, {last_detection['rssi']} dBm)"
        )
    else:
        click.echo("Last detection: none")


@cli.command("test-webhook")
@click.pass_context
def test_webhook(ctx):
    """Send a test notification to the configured webhook URL."""
    from ssid_monitor.alerter import send_alert

    config = ctx.obj.get("config")
    if config is None:
        click.echo("Error: No config file found. Run 'dpmb init' first.", err=True)
        ctx.exit(2)

    payload = {
        "type": "test",
        "device_id": config.device_id,
        "message": "DPMB webhook test",
    }

    status_code, response_text = send_alert(config.webhook_url, payload)
    if status_code > 0:
        click.echo(f"Webhook test sent. Status: {status_code} OK.")
    else:
        click.echo(f"Webhook test failed. {response_text}", err=True)
        ctx.exit(3)


@cli.command()
@click.option("--before", required=True, help="Delete events before this datetime (ISO 8601)")
@click.option("--confirm", is_flag=True, help="Required to actually delete events")
@click.pass_context
def purge(ctx, before, confirm):
    """Permanently delete detection events before a date."""
    if not confirm:
        click.echo("Error: --confirm flag required to delete events. This action is irreversible.", err=True)
        ctx.exit(1)

    # Normalize the before datetime
    if "T" not in before:
        before = before + "T00:00:00Z"

    db = _get_db(ctx)
    cursor = db.execute(
        "DELETE FROM detection_events WHERE detected_at < ?", (before,)
    )
    db.commit()
    click.echo(f"Purged {cursor.rowcount:,} events before {before}.")


@cli.command()
@click.pass_context
def heartbeat(ctx):
    """Send a heartbeat notification (used by systemd timer)."""
    from ssid_monitor.heartbeat import send_heartbeat

    config = ctx.obj.get("config")
    if config is None:
        click.echo("Error: No config file found. Run 'dpmb init' first.", err=True)
        ctx.exit(2)

    db = _get_db(ctx)
    status_code, response_text = send_heartbeat(config, db)

    if status_code > 0:
        click.echo(f"Heartbeat sent. Status: {status_code} OK.")
    else:
        click.echo(f"Heartbeat failed. {response_text}", err=True)
        ctx.exit(3)


@cli.command()
@click.option("--port", default=5000, help="Port to listen on (default 5000)")
@click.pass_context
def dashboard(ctx, port):
    """Launch the live probe request dashboard (web UI on port 5000)."""
    from ssid_monitor.dashboard import app, DB_PATH
    import ssid_monitor.dashboard as dash

    config = ctx.obj.get("config")
    if config:
        dash.DB_PATH = config.db_path

    click.echo(f"Dashboard starting on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
