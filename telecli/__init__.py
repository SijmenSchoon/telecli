from curses import wrapper
import os
import json


class Config:
    CONFIG_DIR = os.path.join(os.environ['XDG_CONFIG_HOME'], 'telecli')
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
    'welcome_message': [
        'Welcome to TeleCLI!',
        'Please enter your phone number to begin:'
    ]
}

def add_center(stdscr, y, half_x, str):
    stdscr.addstr(y, half_x - len(str) // 2, str)

def main(stdscr):
    stdscr.clear()

    if config['auth_key_id'] is None:
        max_y, max_x = stdscr.getmaxyx()
        half_y, half_x = (max_y // 2, max_x // 2)

        add_center(stdscr, half_y - 3, half_x, strings['welcome_message'][0])
        add_center(stdscr, half_y - 2, half_x, strings['welcome_message'][1])

        stdscr.refresh()
        stdscr.getkey()

config = Config()
print(config)
wrapper(main)