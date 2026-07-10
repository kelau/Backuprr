import argparse
import json
from pathlib import Path

from . import __version__
from .backup import post_next, verify_due_chunks
from .cloud_backup import backup_config_and_database
from .config import Config
from .db import Database
from .operations import check_usenet_hosts, dry_run_plan, restore_confidence, run_maintenance, run_restore_drill
from .queueing import enqueue_unbacked, move, prioritize
from .restore import restore_file, restore_folder
from .scanner import scan_all
from .web import run_web


def load_db(config_path: str) -> tuple[Config, Database]:
    config = Config.load(config_path)
    db = Database(config.db_path())
    return config, db


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="backuprr")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--version", action="version", version=f"backuprr {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    add_endpoint = sub.add_parser("add-endpoint")
    add_endpoint.add_argument("path")
    sub.add_parser("scan")
    sub.add_parser("status")
    queue = sub.add_parser("queue")
    queue_sub = queue.add_subparsers(dest="queue_command", required=True)
    queue_sub.add_parser("list")
    queue_sub.add_parser("enqueue-unbacked")
    qprio = queue_sub.add_parser("prioritize")
    qprio.add_argument("--filter", default="older-first", choices=["older-first", "larger-first", "smaller-first"])
    qmove = queue_sub.add_parser("move")
    qmove.add_argument("file_id", type=int)
    qmove.add_argument("position", type=int)
    sub.add_parser("post-next")
    verify = sub.add_parser("verify")
    verify.add_argument("--force", action="store_true")
    sub.add_parser("cloud-backup")
    sub.add_parser("dry-run")
    sub.add_parser("health-check")
    maintenance = sub.add_parser("maintenance")
    maintenance.add_argument("--vacuum", action="store_true")
    sub.add_parser("restore-drill")
    pause = sub.add_parser("pause")
    pause.add_argument("kind", nargs="?", default="all")
    resume = sub.add_parser("resume")
    resume.add_argument("kind", nargs="?", default="all")
    restore = sub.add_parser("restore")
    restore.add_argument("--path", required=True)
    restore.add_argument("--dest")
    restore.add_argument("--folder", action="store_true")
    web = sub.add_parser("web")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    config, db = load_db(args.config)

    if args.command == "init":
        db.init()
        if not Path(args.config).exists():
            config.save(args.config)
        print(f"Initialized {config.db_path()}")
        return 0
    db.init()
    if args.command == "add-endpoint":
        db.add_endpoint(args.path)
        if str(Path(args.path).resolve()) not in config.endpoints:
            config.endpoints.append(str(Path(args.path).resolve()))
            config.save(args.config)
        print(f"Added endpoint {Path(args.path).resolve()}")
    elif args.command == "scan":
        print(f"Scanned {scan_all(db)} files")
    elif args.command == "status":
        print(json.dumps(db.stats(), indent=2, sort_keys=True))
    elif args.command == "queue":
        if args.queue_command == "list":
            rows = db.list_rows("queue")
            print(json.dumps([dict(row) for row in rows], indent=2))
        elif args.queue_command == "enqueue-unbacked":
            print(f"Queued {enqueue_unbacked(db, config)} files")
        elif args.queue_command == "prioritize":
            print(f"Reordered {prioritize(db, args.filter)} queued files")
        elif args.queue_command == "move":
            move(db, args.file_id, args.position)
            print("Moved")
    elif args.command == "post-next":
        posted = post_next(db, config)
        print("No queued file" if posted is None else f"Posted file id {posted}")
    elif args.command == "verify":
        print(f"Verified {verify_due_chunks(db, config, force=args.force)} chunks")
    elif args.command == "cloud-backup":
        print(json.dumps(backup_config_and_database(db, config), indent=2))
    elif args.command == "dry-run":
        print(json.dumps(dry_run_plan(db, config), indent=2))
    elif args.command == "health-check":
        print(json.dumps(check_usenet_hosts(db, config), indent=2))
    elif args.command == "maintenance":
        print(json.dumps(run_maintenance(db, config, vacuum=args.vacuum), indent=2))
    elif args.command == "restore-drill":
        print(json.dumps(run_restore_drill(db, config), indent=2))
    elif args.command == "pause":
        db.set_paused(args.kind, True)
        print(f"Paused {args.kind}")
    elif args.command == "resume":
        db.set_paused(args.kind, False)
        print(f"Resumed {args.kind}")
    elif args.command == "restore":
        print(json.dumps(restore_confidence(db, args.path), indent=2))
        if args.folder:
            print(f"Restored {restore_folder(db, config, args.path, args.dest)} files")
        else:
            print(f"Restored to {restore_file(db, config, args.path, args.dest)}")
    elif args.command == "web":
        run_web(config, db, args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
