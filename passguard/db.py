import sqlite3

import click
from flask import current_app, g

# Gets a link from the database using the global application context g
def get_db():

    # check if the db is already in g
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
    return g.db

# Gets the db connection from g and closes it if it exists.
def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()

# Reads the schema file to initialize the database
def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

# Command to initialize the database
@click.command('init-db')
def init_db_command():
    # Clear Existing data and create new tables.
    init_db()
    click.echo('Initialized the database.')

# Takes the app instance as an argument so get_db() and close_db() can be registered when app is called.
def init_app(app):
    # Tells the app to use close_db when cleaning up after a response
    app.teardown_appcontext(close_db)

    # Adds a command to initialize the db from the flask commands
    app.cli.add_command(init_db_command)