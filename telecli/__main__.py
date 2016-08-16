import asyncio
import curses
import os
import sys

import appdirs
from ruamel import yaml

sys.path.insert(1, os.path.join(sys.path[0], '..'))
import mtproto.datacenter


class Config:
    CONFIG_DIR = appdirs.user_config_dir('telecli')
    CONFIG_FILE = 'config.yml'
    CONFIG_PATH = os.path.join(CONFIG_DIR, CONFIG_FILE)

    def __init__(self):
        self.config = {}
        self.read()
        self.write()

    def read(self):
        # Read the config file
        try:
            with open(self.CONFIG_PATH, 'r') as f:
                self.config = yaml.load(f)
        except FileNotFoundError:
            pass

    def write(self):
        # Make sure the directory exists
        os.makedirs(self.CONFIG_DIR, exist_ok=True)

        # Write the config file
        with open(self.CONFIG_PATH, 'w') as f:
            yaml.dump(self.config, f)

    def __str__(self):
        return yaml.dump(self.config)

    def __getitem__(self, item):
        return self.config[item]

    def __setitem__(self, key, value):
        self.config[key] = value

    def __contains__(self, item):
        return item in self.config


strings = {
    'connecting': 'Connecting...',
    'performing_handshake': (
        'Performing handshake...',
        '(this may take a while)'
    ),
    'auth_key': 'Authentication key ID: {:#x}',
    'welcome_message': (
        'Welcome to TeleCLI!',
        'Please enter your phone number to begin',
        '(with country code, without special',
        'characters, like +31612345678):',
        '> +'
    )
}


async def main(stdscr):
    max_y, max_x = stdscr.getmaxyx()
    half_y, half_x = (max_y // 2, max_x // 2)

    curses.noecho()

    stdscr.clear()
    stdscr.addstr(half_y, 0, strings['connecting'].center(max_x))
    stdscr.refresh()
    await dc.connect()

    if dc.auth_key_id == 0:
        stdscr.clear()
        stdscr.addstr(half_y - 1, 0, strings['performing_handshake'][0].center(max_x))
        stdscr.addstr(half_y, 0, strings['performing_handshake'][1].center(max_x))
        stdscr.refresh()
        await dc.handshake()
        config['datacenter'] = dc.config
        config.write()

    stdscr.clear()
    stdscr.addstr(half_y - 5, 0, strings['auth_key'].format(dc.auth_key_id).center(max_x))
    stdscr.addstr(half_y - 3, 0, strings['welcome_message'][0].center(max_x))
    stdscr.addstr(half_y - 2, 0, strings['welcome_message'][1].center(max_x))
    stdscr.addstr(half_y - 1, 0, strings['welcome_message'][2].center(max_x))
    stdscr.addstr(half_y - 0, 0, strings['welcome_message'][3].center(max_x))

    stdscr.addstr(half_y + 2, half_x - 10, strings['welcome_message'][4])
    stdscr.refresh()

    phone_num = ''
    while True:
        c = stdscr.getch()
        if c == curses.KEY_BACKSPACE or c == 127:
            phone_num = phone_num[:-1]
            stdscr.move(half_y + 2, half_x - 7 + len(phone_num))
            stdscr.delch()
        elif c == curses.KEY_ENTER:
            # register phone number
            pass
        elif ord('0') <= c <= ord('9') and len(phone_num) <= 15:
            phone_num += chr(c)
            stdscr.echochar(c)


async def start():
    await curses.wrapper(main)

config = Config()
loop = asyncio.get_event_loop()
dc = mtproto.datacenter.Datacenter()
if 'datacenter' in config:
    dc.config = config['datacenter']

loop.run_until_complete(start())
