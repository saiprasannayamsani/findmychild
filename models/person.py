from datetime import datetime

class MissingPerson:
    def __init__(self, case_id, name, age, gender, location, date, desc,
                 missing_aadhaar, birth_cert_reg, cert_filename,
                 reporter_name, reporter_email, reporter_aadhaar,
                 phone, relation, priority, status="Missing", escalation="LOCAL",
                 child_photo=""):
        self.case_id          = case_id
        self.name             = name
        self.age              = age
        self.gender           = gender
        self.location         = location
        self.date             = date
        self.desc             = desc
        self.missing_aadhaar  = missing_aadhaar   # last 4 digits only
        self.birth_cert_reg   = birth_cert_reg
        self.cert_filename    = cert_filename
        self.child_photo      = child_photo        # filename of uploaded child photo
        self.reporter_name    = reporter_name
        self.reporter_email   = reporter_email
        self.reporter_aadhaar = reporter_aadhaar   # last 4 digits only
        self.phone            = phone
        self.relation         = relation
        self.priority         = priority
        self.status           = status
        self.escalation       = escalation
        self.reported_at      = datetime.now().strftime("%d %b %Y %H:%M")

    def to_dict(self):
        return vars(self)
