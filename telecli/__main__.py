import curses, json, os, appdirs, sys, asyncio
sys.path.insert(1, os.path.join(sys.path[0], '..'))
import mtproto.datacenter


class Config:
    CONFIG_DIR = appdirs.user_config_dir('telecli')
    CONFIG_FILE = 'config.json'
    CONFIG_PATH = os.path.join(CONFIG_DIR, CONFIG_FILE)

    def __init__(self):
        self.config = {}
        self.read()
        self.write()

    def read(self):
        # Read the config file
        try:
            with open(self.CONFIG_PATH, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            pass

        if 'auth_key_id' not in self.config:
            self.config['auth_key_id'] = None

    def write(self):
        # Make sure the directory exists
        os.makedirs(self.CONFIG_DIR, exist_ok=True)

        # Write the config file
        with open(self.CONFIG_PATH, 'w') as f:
            json.dump(self.config, f, indent=2)

    def __str__(self):
        return json.dumps(self.config, indent=2)

    def __getitem__(self, item):
        return self.config[item]


strings = {
    'busy_indicator': ('|', '/', '-', '\\'),

    'performing_handshake': 'Performing handshake...',

    'welcome_message': (
        'Welcome to TeleCLI!',
        'Please enter your phone number to begin',
        '(with country code, without special',
        'characters, like +31612345678):',
        '> +'
    )
}


def add_center(stdscr, y, half_x, str):
    stdscr.addstr(y, half_x - len(str) // 2, str)


async def main(stdscr):
    curses.noecho()
    stdscr.clear()

    if config['auth_key_id'] is None:
        max_y, max_x = stdscr.getmaxyx()
        half_y, half_x = (max_y // 2, max_x // 2)

        stdscr.addstr(half_y, 0, strings['performing_handshake'].center(max_x))
        await dc.connect()
        await dc.handshake()

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

loop.run_until_complete(start())
