from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    usn = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default="user", nullable=False)

    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    item_name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(150), nullable=False)

    date_lost = db.Column(db.Date, nullable=True)
    date_found = db.Column(db.Date, nullable=True)

    report_type = db.Column(db.String(10), nullable=False)

    status = db.Column(
        db.String(20),
        default="Active",
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )

    images = db.relationship(
        "ItemImage",
        backref="item",
        cascade="all, delete-orphan"
    )

    claims = db.relationship(
        "Claim",
        backref="item",
        cascade="all, delete-orphan"
    )


class ItemImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    item_id = db.Column(
        db.Integer,
        db.ForeignKey("item.id"),
        nullable=False
    )

    filename = db.Column(db.String(255), nullable=False)


class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    item_id = db.Column(
        db.Integer,
        db.ForeignKey("item.id"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    message = db.Column(db.Text, nullable=False)

    status = db.Column(
        db.String(20),
        default="Pending",
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )

    user = db.relationship("User", backref="claims")

    images = db.relationship(
        "ClaimImage",
        backref="claim",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        db.UniqueConstraint(
            "item_id",
            "user_id",
            name="unique_user_item_claim"
        ),
    )


class ClaimImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    claim_id = db.Column(
        db.Integer,
        db.ForeignKey("claim.id"),
        nullable=False
    )

    filename = db.Column(db.String(255), nullable=False)


# -----------------------------------------
# NOTIFICATIONS
# -----------------------------------------

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    claim_id = db.Column(
        db.Integer,
        db.ForeignKey("claim.id"),
        nullable=True
    )

    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)

    is_read = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )

    user = db.relationship(
        "User",
        backref=db.backref("notifications", lazy=True)
    )

    claim = db.relationship("Claim")
