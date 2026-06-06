from datetime import datetime

class Case:
    def __init__(self, case_id, missing, found, status):
        self.case_id     = case_id
        self.missing     = missing
        self.found       = found
        self.status      = status
        self.created_at  = datetime.now().strftime("%d %b %Y %H:%M")
        self.resolved_at = None

    def to_dict(self):
        return vars(self)
