import os

from flask import Flask


def create_app(test_config=None):
    # Create and Configure the App
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE = os.path.join(app.instance_path, 'passguard.sqlite')
    )

    if test_config is None:
        # Load instance config if not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # call init_app() when create_app() is called to tell flask how to clear the db connection
    from . import db
    db.init_app(app)

    # import all auth blueprints
    from . import auth
    app.register_blueprint(auth.bp)

    from . import pages
    app.register_blueprint(pages.bp)

    return app

