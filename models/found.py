from datetime import datetime

class FoundPerson:
    def __init__(self, case_id, age, gender, location, condition, desc, phone, aadhaar, found_photo="", reporter_email="", found_name=""):
        self.case_id        = case_id
        self.found_name     = found_name   # optional — person's name if they told you
        self.age            = age
        self.gender         = gender
        self.location       = location
        self.condition      = condition
        self.desc           = desc
        self.phone          = phone
        self.aadhaar        = aadhaar
        self.found_photo    = found_photo
        self.reporter_email = reporter_email
        self.reported_at    = datetime.now().strftime("%d %b %Y %H:%M")

    def to_dict(self):
        return vars(self)
