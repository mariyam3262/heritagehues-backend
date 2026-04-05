from flask_login import UserMixin
from bson import ObjectId


class Admin(UserMixin):
    def __init__(self, document):
        self.document = document or {}
        self.id = str(self.document.get("_id", ""))
        self.name = self.document.get("name", "")
        self.email = self.document.get("email", "")
        self.password = self.document.get("password", "")
        self.role = self.document.get("role", "admin")
        self.created_at = self.document.get("created_at")

    @classmethod
    def from_document(cls, document):
        if not document:
            return None
        return cls(document)

    @staticmethod
    def normalize_id(value):
        try:
            return ObjectId(str(value))
        except Exception:
            return None

    def get_id(self):
        return self.id

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at,
        }
