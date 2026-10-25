"""Offline-only local administrator bootstrap and password recovery."""
import argparse
import getpass
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from .auth import create_auth_tables, initialize_admin, recover_admin_password
from .models import AdminAccount


def _database_path():
    data_dir = Path(os.getenv('AVA_DATA_DIR', 'data')).resolve()
    database = data_dir / 'assessment.sqlite3'
    if not database.is_file():
        raise RuntimeError(
            f'Existing PATROLMAN database was not found at {database}. '
            'Run this command from the project root or set AVA_DATA_DIR to its existing data directory.'
        )
    return database


def _password_pair():
    password = getpass.getpass('New administrator password (minimum 8 characters): ')
    confirmation = getpass.getpass('Confirm administrator password: ')
    return password, confirmation


def main(argv=None):
    parser = argparse.ArgumentParser(description='Local-only PATROLMAN administrator maintenance.')
    subparsers = parser.add_subparsers(dest='command', required=True)
    subparsers.add_parser('setup', help='Create the first administrator when none exists.')
    subparsers.add_parser('recover', help='Reset an administrator password and revoke that account\'s sessions.')
    args = parser.parse_args(argv)
    engine = None
    try:
        database = _database_path()
        engine = create_engine('sqlite:///' + database.as_posix(), connect_args={'timeout': 10})
        create_auth_tables(engine)
        with Session(engine) as session:
            initialized = session.scalar(select(AdminAccount.id).limit(1)) is not None
        if args.command == 'setup' and initialized:
            raise RuntimeError(
                'An administrator account already exists. '
                'Use the Admin Sign Up page to add another administrator.'
            )
        if args.command == 'recover' and not initialized:
            raise RuntimeError('The PATROLMAN administrator has not been initialized.')
        if args.command == 'setup':
            username = input('Administrator username: ')
            password, confirmation = _password_pair()
            initialize_admin(engine, username, password, confirmation)
            print('PATROLMAN administrator initialized.')
        else:
            username = input('Existing administrator username: ')
            password, confirmation = _password_pair()
            recover_admin_password(engine, username, password, confirmation)
            print('PATROLMAN administrator password updated; existing sessions were revoked.')
        return 0
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == '__main__':
    raise SystemExit(main())
