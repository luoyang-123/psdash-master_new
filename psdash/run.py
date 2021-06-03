import gevent
from gevent.monkey import patch_all
patch_all()

from gevent.pywsgi import WSGIServer
import locale
import argparse
import logging
from logging import getLogger
from flask import Flask
from psdash import __version__
from psdash.node import LocalNode, RemoteNode
from psdash.web import fromtimestamp


logger = getLogger('psdash.run')

class PsDashRunner(object):
    DEFAULT_LOG_INTERVAL = 60
    DEFAULT_NET_IO_COUNTER_INTERVAL = 3
    DEFAULT_REGISTER_INTERVAL = 60
    DEFAULT_BIND_HOST = '0.0.0.0'
    DEFAULT_PORT = 6606
    LOCAL_NODE = 'localhost'

    @classmethod
    def create_from_cli_args(cls):
        return cls(args=None)

    def __init__(self, config_overrides=None, args=tuple()):
        self._nodes = {}
        config = self._load_args_config(args)
        if config_overrides:
            config.update(config_overrides)
        self.app = self._create_app(config)

        self.add_node(LocalNode())
        self._setup_logging()
        self._setup_context()

    def _get_args(cls, args):
        parser = argparse.ArgumentParser(
            description='psdash %s - system information web dashboard' % __version__
        )

        parser.add_argument(
            '-l', '--log',
            action='append',
            dest='logs',
            default=None,
            metavar='path',
            help='log files to make available for psdash. Patterns (e.g. /var/log/**/*.log) are supported. '
                 'This option can be used multiple times.'
        )
        parser.add_argument(
            '-p', '--port',
            action='store',
            type=int,
            dest='port',
            default=None,
            metavar='port',
            help='port to listen on. Defaults to 5000.'
        )
        parser.add_argument(
            '-d', '--debug',
            action='store_true',
            dest='debug',
            help='enables debug mode.'
        )

        return parser.parse_args(args)

    def _load_args_config(self, args):
        config = {}
        for k, v in vars(self._get_args(args)).iteritems():
            if v:
                key = 'PSDASH_%s' % k.upper() if k != 'debug' else 'DEBUG'
                config[key] = v
        return config


    def add_node(self, node):
        self._nodes[node.get_id()] = node

    def get_local_node(self):
        return self._nodes.get(self.LOCAL_NODE)

    def get_node(self, name):
        return self._nodes.get(name)

    def get_nodes(self):
        return self._nodes

    def _create_app(self, config=None):
        app = Flask(__name__)
        app.psdash = self
        app.config.from_envvar('PSDASH_CONFIG', silent=True)

        if config and isinstance(config, dict):
            app.config.update(config)

        self._load_allowed_remote_addresses(app)

        # If the secret key is not read from the config just set it to something.
        if not app.secret_key:
            app.secret_key = 'whatisthissourcery'
        app.add_template_filter(fromtimestamp)

        from psdash.web import webapp
        prefix = app.config.get('PSDASH_URL_PREFIX')
        if prefix:
            prefix = '/' + prefix.strip('/')
        webapp.url_prefix = prefix
        app.register_blueprint(webapp)

        return app

    def _load_allowed_remote_addresses(self, app):
        key = 'PSDASH_ALLOWED_REMOTE_ADDRESSES'
        addrs = app.config.get(key)
        if not addrs:
            return

        if isinstance(addrs, (str, unicode)):
            app.config[key] = [a.strip() for a in addrs.split(',')]

    def _setup_logging(self):
        level = self.app.config.get('PSDASH_LOG_LEVEL', logging.INFO) if not self.app.debug else logging.DEBUG
        format = self.app.config.get('PSDASH_LOG_FORMAT', '%(levelname)s | %(name)s | %(message)s')

        logging.basicConfig(
            level=level,
            format=format
        )
        logging.getLogger('werkzeug').setLevel(logging.WARNING if not self.app.debug else logging.DEBUG)


    def _setup_context(self):
        self.get_local_node().net_io_counters.update()
        if 'PSDASH_LOGS' in self.app.config:
            self.get_local_node().logs.add_patterns(self.app.config['PSDASH_LOGS'])


    def run(self):
        logger.info('Starting psdash v%s' % __version__)

        logger.info('Listening on %s:%s',
                    self.app.config.get('PSDASH_BIND_HOST', self.DEFAULT_BIND_HOST),
                    self.app.config.get('PSDASH_PORT', self.DEFAULT_PORT))

        logger.info("Starting web server")
        log = 'default' if self.app.debug else None

        ssl_args = {}
        if self.app.config.get('PSDASH_HTTPS_KEYFILE') and self.app.config.get('PSDASH_HTTPS_CERTFILE'):
            ssl_args = {
                'keyfile': self.app.config.get('PSDASH_HTTPS_KEYFILE'),
                'certfile': self.app.config.get('PSDASH_HTTPS_CERTFILE')
            }

        listen_to = (
            self.app.config.get('PSDASH_BIND_HOST', self.DEFAULT_BIND_HOST),
            self.app.config.get('PSDASH_PORT', self.DEFAULT_PORT)
        )
        self.server = WSGIServer(
            listen_to,
            application=self.app,
            log=log,
            **ssl_args
        )
        self.server.serve_forever()

def main():
    r = PsDashRunner.create_from_cli_args()
    r.run()

if __name__ == '__main__':
    main()