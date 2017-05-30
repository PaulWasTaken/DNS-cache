from threading import Timer, RLock


class TTLTimer:
    def __init__(self, func):
        self.interval = 1
        self.func = func

        self.timer = None

    def callback(self):
        with RLock():
            self.func()
        self.start()

    def cancel(self):
        self.timer.cancel()

    def start(self):
        self.timer = Timer(self.interval, self.callback)
        self.timer.daemon = True
        self.timer.start()
