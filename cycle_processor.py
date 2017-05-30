class CycleError(Exception):
    pass


class CycleProcessor:
    def __init__(self):
        self.query_id = {}

    def add_id(self, id_):
        if id_ not in self.query_id:
            self.query_id[id_] = 0
        self.query_id[id_] += 1

    def is_cycle(self, id_):
        self.add_id(id_)
        return self.query_id[id_] >= 5

    def delete_id(self, id_):
        del self.query_id[id_]
