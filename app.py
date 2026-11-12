import os
from dotenv import load_dotenv

load_dotenv()
import uuid
import re
from difflib import SequenceMatcher
from functools import wraps
from datetime import datetime
from io import BytesIO

from PIL import Image, ImageOps, UnidentifiedImageError

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory,
    jsonify,
)

from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, CSRFError

from models import (
    db,
    User,
    Admin,
    Item,
    ItemImage,
    Claim,
    ClaimImage,
    Notification,
)


# -----------------------------------------
# APPLICATION CONFIGURATION
# -----------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY environment variable is not set.")

database_url = os.environ.get("DATABASE_URL")

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://",
            "postgresql://",
            1
        )
else:
    database_url = "sqlite:///cec_lost_found.db"

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["UPLOAD_FOLDER"] = os.path.join(
    app.root_path,
    "uploads"
)

app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
)

app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = 3600

csrf = CSRFProtect(app)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {
    "png", "jpg", "jpeg", "webp"
}

IMAGE_FORMATS = {
    "png": "PNG",
    "jpg": "JPEG",
    "jpeg": "JPEG",
    "webp": "WEBP",
}

MAX_IMAGE_PIXELS = 20_000_000


# -----------------------------------------
# SECURITY AND UPLOAD ERROR HANDLERS
# -----------------------------------------

@app.errorhandler(CSRFError)
def handle_csrf_error(error):

    app.logger.warning(
        "CSRF validation failed: %s",
        error.description
    )

    return (
        "Your session may have expired or the form token is invalid. "
        "Refresh the page and try again.",
        400
    )


@app.errorhandler(413)
def handle_file_too_large(error):

    return (
        "The uploaded file is too large. "
        "The maximum request size is 20 MB.",
        413
    )


# -----------------------------------------
# IMAGE CONTENT VALIDATION
# -----------------------------------------

def validate_and_sanitize_image(image_file):
    """
    Validate actual image content, not just its filename.
    Returns the extension and sanitized image bytes.
    """

    if image_file is None or not image_file.filename:
        raise ValueError("No image was selected.")

    filename = secure_filename(image_file.filename)

    if "." not in filename:
        raise ValueError("The image filename has no valid extension.")

    extension = filename.rsplit(".", 1)[-1].lower()

    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError(
            "Only PNG, JPG, JPEG and WEBP images are allowed."
        )

    expected_format = IMAGE_FORMATS[extension]

    try:

        image_file.stream.seek(0)

        with Image.open(image_file.stream) as probe:

            detected_format = probe.format
            width, height = probe.size

            if detected_format != expected_format:
                raise ValueError(
                    "The file content does not match its image extension."
                )

            if (
                width <= 0
                or height <= 0
                or width * height > MAX_IMAGE_PIXELS
            ):
                raise ValueError(
                    "The image dimensions are invalid or too large."
                )

            probe.verify()

        image_file.stream.seek(0)

        with Image.open(image_file.stream) as original:

            if original.format != expected_format:
                raise ValueError(
                    "The file content does not match its image extension."
                )

            original.load()

            cleaned = ImageOps.exif_transpose(original)

            if expected_format == "JPEG":

                if cleaned.mode not in ("RGB", "L"):
                    cleaned = cleaned.convert("RGB")

            elif expected_format == "PNG":

                if cleaned.mode not in (
                    "RGB", "RGBA", "L", "LA", "P"
                ):
                    cleaned = cleaned.convert("RGBA")

            else:

                if cleaned.mode not in ("RGB", "RGBA"):
                    cleaned = cleaned.convert("RGBA")

            output = BytesIO()

            cleaned.save(
                output,
                format=expected_format
            )

            output.seek(0)

            return extension, output.read()

    except ValueError:
        raise

    except (
        UnidentifiedImageError,
        OSError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning
    ) as error:

        raise ValueError(
            "The uploaded file is not a valid supported image."
        ) from error

    finally:
        image_file.stream.seek(0)


def save_validated_image(image_file):

    extension, image_bytes = validate_and_sanitize_image(
        image_file
    )

    unique_name = f"{uuid.uuid4().hex}.{extension}"

    save_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        unique_name
    )

    with open(save_path, "wb") as destination:
        destination.write(image_bytes)

    return unique_name, save_path


# -----------------------------------------
# DATABASE INITIALIZATION
# -----------------------------------------

db.init_app(app)

with app.app_context():
    db.create_all()


# -----------------------------------------
# LOGIN REQUIRED DECORATOR
# -----------------------------------------

def login_required(role=None):

    def decorator(view_function):

        @wraps(view_function)
        def wrapped_view(*args, **kwargs):

            if "user_id" not in session:

                flash("Please sign in first.", "error")
                return redirect(url_for("login"))

            current_role = session.get("role")

            if current_role not in ("user", "admin"):

                session.clear()

                flash("Please sign in again.", "error")
                return redirect(url_for("login"))

            if role and current_role != role:

                flash(
                    "You are not authorized to access that page.",
                    "error"
                )

                return redirect(url_for("login"))

            if current_role == "user":

                student = db.session.get(
                    User,
                    session["user_id"]
                )

                if student is None or not student.is_active:

                    session.clear()

                    flash(
                        "Your account is inactive. Please contact the administrator.",
                        "error"
                    )

                    return redirect(url_for("login"))

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator


# -----------------------------------------
# HOME
# -----------------------------------------

@app.route("/")
def home():

    if session.get("role") == "user":
        return redirect(url_for("student_dashboard"))

    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    return redirect(url_for("login"))


# -----------------------------------------
# STUDENT REGISTRATION
# -----------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get(
            "full_name", ""
        ).strip()

        usn = request.form.get(
            "usn", ""
        ).strip().upper()

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not all([
            full_name,
            usn,
            password,
            confirm_password
        ]):

            flash(
                "Please fill in all the fields.",
                "error"
            )

            return redirect(url_for("register"))

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "error"
            )

            return redirect(url_for("register"))

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(url_for("register"))

        if User.query.filter_by(usn=usn).first():

            flash(
                "This USN is already registered.",
                "error"
            )

            return redirect(url_for("register"))

        new_user = User(
            full_name=full_name,
            usn=usn,
            role="user",
            is_active=True
        )

        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash(
            "Account created successfully. You can now sign in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# -----------------------------------------
# LOGIN
# -----------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        login_type = request.form.get("login_type", "")

        identifier = request.form.get(
            "identifier", ""
        ).strip()

        password = request.form.get("password", "")

        if not identifier or not password:

            flash(
                "Please enter your login details.",
                "error"
            )

            return redirect(url_for("login"))

        account = None

        if login_type == "student":

            account = User.query.filter_by(
                usn=identifier.upper(),
                role="user"
            ).first()

            if account and not account.is_active:

                flash(
                    "Your account has been deactivated. Please contact the administrator.",
                    "error"
                )

                return redirect(url_for("login"))

        elif login_type == "admin":

            account = Admin.query.filter_by(
                username=identifier
            ).first()

        else:

            flash(
                "Please select a valid account type.",
                "error"
            )

            return redirect(url_for("login"))

        if not account or not account.check_password(password):

            flash(
                "Invalid login details.",
                "error"
            )

            return redirect(url_for("login"))

        session.clear()

        if login_type == "student":

            session["user_id"] = account.id
            session["role"] = "user"
            session["display_name"] = account.full_name

            return redirect(url_for("student_dashboard"))

        session["user_id"] = account.id
        session["role"] = "admin"
        session["display_name"] = account.username

        return redirect(url_for("admin_dashboard"))

    return render_template("login.html")
    # -----------------------------------------
# STUDENT DASHBOARD
# -----------------------------------------

@app.route("/student/dashboard")
@login_required(role="user")
def student_dashboard():

    user = db.session.get(
        User,
        session["user_id"]
    )

    unread_notifications = Notification.query.filter_by(
        user_id=user.id,
        is_read=False
    ).count()

    recent_notifications = Notification.query.filter_by(
        user_id=user.id
    ).order_by(
        Notification.created_at.desc()
    ).limit(5).all()

    return render_template(
        "dashboard.html",
        user=user,
        unread_notifications=unread_notifications,
        recent_notifications=recent_notifications
    )


# -----------------------------------------
# API - FETCH LATEST NOTIFICATIONS
# -----------------------------------------

@app.route("/api/notifications")
@login_required(role="user")
def api_notifications():

    user_id = session["user_id"]

    unread_count = Notification.query.filter_by(
        user_id=user_id,
        is_read=False
    ).count()

    recent_notifications = Notification.query.filter_by(
        user_id=user_id
    ).order_by(
        Notification.created_at.desc()
    ).limit(5).all()

    notification_data = []

    for notification in recent_notifications:

        notification_data.append({
            "id": notification.id,
            "title": notification.title,
            "message": notification.message,
            "is_read": notification.is_read,
            "created_at": notification.created_at.strftime(
                "%d %b %Y, %I:%M %p"
            )
        })

    response = jsonify({
        "unread_count": unread_count,
        "notifications": notification_data
    })

    response.headers["Cache-Control"] = "no-store"

    return response


# -----------------------------------------
# ADMIN DASHBOARD
# -----------------------------------------

@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():

    total_claims = Claim.query.count()

    pending_claims = Claim.query.filter_by(
        status="Pending"
    ).count()

    approved_claims = Claim.query.filter_by(
        status="Approved"
    ).count()

    rejected_claims = Claim.query.filter_by(
        status="Rejected"
    ).count()

    recent_claims = Claim.query.order_by(
        Claim.created_at.desc()
    ).limit(5).all()

    return render_template(
        "admin_dashboard.html",
        total_claims=total_claims,
        pending_claims=pending_claims,
        approved_claims=approved_claims,
        rejected_claims=rejected_claims,
        recent_claims=recent_claims
    )


# -----------------------------------------
# ADMIN - STUDENT MANAGEMENT
# -----------------------------------------

@app.route("/admin/students")
@login_required(role="admin")
def admin_students():

    search = request.args.get(
        "search", ""
    ).strip()

    query = User.query.filter_by(role="user")

    total_students = User.query.filter_by(
        role="user"
    ).count()

    if search:

        search_term = f"%{search}%"

        query = query.filter(
            db.or_(
                User.full_name.ilike(search_term),
                User.usn.ilike(search_term)
            )
        )

    students = query.order_by(
        User.full_name.asc()
    ).all()

    return render_template(
        "admin_students.html",
        students=students,
        search=search,
        total_students=total_students
    )


# -----------------------------------------
# ADMIN - VIEW STUDENT DETAILS
# -----------------------------------------

@app.route("/admin/students/<int:student_id>")
@login_required(role="admin")
def admin_student_details(student_id):

    student = User.query.filter_by(
        id=student_id,
        role="user"
    ).first()

    if student is None:

        flash(
            "Student not found.",
            "error"
        )

        return redirect(url_for("admin_students"))

    student_reports = Item.query.filter_by(
        user_id=student.id
    ).order_by(
        Item.created_at.desc()
    ).all()

    student_claims = Claim.query.filter_by(
        user_id=student.id
    ).order_by(
        Claim.created_at.desc()
    ).all()

    return render_template(
        "admin_student_details.html",
        student=student,
        student_reports=student_reports,
        student_claims=student_claims
    )


# -----------------------------------------
# ADMIN - ACTIVATE / DEACTIVATE STUDENT
# -----------------------------------------

@app.route(
    "/admin/students/<int:student_id>/toggle",
    methods=["POST"]
)
@login_required(role="admin")
def toggle_student_status(student_id):

    student = User.query.filter_by(
        id=student_id,
        role="user"
    ).first()

    if student is None:

        flash(
            "Student not found.",
            "error"
        )

        return redirect(url_for("admin_students"))

    try:

        student.is_active = not student.is_active

        db.session.commit()

        if student.is_active:

            flash(
                f"{student.full_name}'s account has been activated.",
                "success"
            )

        else:

            flash(
                f"{student.full_name}'s account has been deactivated.",
                "success"
            )

    except Exception:

        db.session.rollback()

        app.logger.exception(
            "Could not update student status"
        )

        flash(
            "Could not update the student account. Please try again.",
            "error"
        )

    return redirect(url_for("admin_students"))


# -----------------------------------------
# ADMIN - REVIEW CLAIMS
# -----------------------------------------

@app.route("/admin/claims")
@login_required(role="admin")
def admin_claims():

    claims = Claim.query.order_by(
        Claim.created_at.desc()
    ).all()

    return render_template(
        "admin_claims.html",
        claims=claims
    )


# -----------------------------------------
# ADMIN - APPROVE CLAIM
# -----------------------------------------

@app.route(
    "/admin/claims/<int:claim_id>/approve",
    methods=["POST"]
)
@login_required(role="admin")
def approve_claim(claim_id):

    claim = db.session.get(
        Claim,
        claim_id
    )

    if claim is None:

        flash(
            "Claim not found.",
            "error"
        )

        return redirect(url_for("admin_claims"))

    if claim.status != "Pending":

        flash(
            "This claim has already been reviewed.",
            "error"
        )

        return redirect(url_for("admin_claims"))

    if claim.item.status != "Active":

        flash(
            "This item is no longer available for claiming.",
            "error"
        )

        return redirect(url_for("admin_claims"))

    try:

        claim.status = "Approved"
        claim.item.status = "Claimed"

        notification = Notification(
            user_id=claim.user_id,
            claim_id=claim.id,
            title="Claim Approved",
            message=(
                f"Your claim for {claim.item.item_name} "
                "has been approved!"
            ),
            is_read=False
        )

        db.session.add(notification)
        db.session.commit()

        flash(
            "Claim approved successfully.",
            "success"
        )

    except Exception:

        db.session.rollback()

        app.logger.exception(
            "Could not approve claim"
        )

        flash(
            "Could not approve the claim. Please try again.",
            "error"
        )

    return redirect(url_for("admin_claims"))


# -----------------------------------------
# ADMIN - REJECT CLAIM
# -----------------------------------------

@app.route(
    "/admin/claims/<int:claim_id>/reject",
    methods=["POST"]
)
@login_required(role="admin")
def reject_claim(claim_id):

    claim = db.session.get(
        Claim,
        claim_id
    )

    if claim is None:

        flash(
            "Claim not found.",
            "error"
        )

        return redirect(url_for("admin_claims"))

    if claim.status != "Pending":

        flash(
            "This claim has already been reviewed.",
            "error"
        )

        return redirect(url_for("admin_claims"))

    try:

        claim.status = "Rejected"

        notification = Notification(
            user_id=claim.user_id,
            claim_id=claim.id,
            title="Claim Rejected",
            message=(
                f"Your claim for {claim.item.item_name} "
                "has been rejected."
            ),
            is_read=False
        )

        db.session.add(notification)
        db.session.commit()

        flash(
            "Claim rejected successfully.",
            "success"
        )

    except Exception:

        db.session.rollback()

        app.logger.exception(
            "Could not reject claim"
        )

        flash(
            "Could not reject the claim. Please try again.",
            "error"
        )

    return redirect(url_for("admin_claims"))


# -----------------------------------------
# LOGOUT
# -----------------------------------------

@app.route("/logout", methods=["POST"])
@login_required()
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))
    # -----------------------------------------
# DUPLICATE REPORT DETECTION
# -----------------------------------------

def normalize_text(value):
    """Normalize text for similarity comparison."""

    value = (value or "").lower()
    value = re.sub(r"[^a-z0-9\s]", " ", value)

    return " ".join(value.split())


def text_similarity(first, second):
    """Return a text similarity score between 0 and 1."""

    first = normalize_text(first)
    second = normalize_text(second)

    if not first or not second:
        return 0.0

    sequence_score = SequenceMatcher(
        None,
        first,
        second
    ).ratio()

    first_words = set(first.split())
    second_words = set(second.split())

    union = first_words | second_words

    token_score = (
        len(first_words & second_words) / len(union)
        if union else 0.0
    )

    return max(sequence_score, token_score)


def find_duplicate_reports(
    report_type,
    item_name,
    category,
    description,
    location
):
    """
    Find potentially similar reports of the same type.

    This is a warning mechanism, not proof that two reports
    refer to the same physical item.
    """

    existing_items = Item.query.filter(
        Item.report_type == report_type,
        Item.status != "Resolved"
    ).order_by(
        Item.created_at.desc()
    ).all()

    matches = []

    for item in existing_items:

        name_score = text_similarity(
            item.item_name,
            item_name
        )

        category_score = (
            1.0
            if normalize_text(item.category)
            == normalize_text(category)
            else 0.0
        )

        description_score = text_similarity(
            item.description,
            description
        )

        location_score = text_similarity(
            item.location,
            location
        )

        total_score = (
            name_score * 0.40
            + category_score * 0.20
            + description_score * 0.25
            + location_score * 0.15
        )

        if name_score >= 0.60 and total_score >= 0.60:

            report_date = (
                item.date_lost
                if item.report_type == "lost"
                else item.date_found
            )

            matches.append({
                "id": item.id,
                "item_name": item.item_name,
                "category": item.category,
                "location": item.location,
                "report_date": (
                    report_date.strftime("%d %b %Y")
                    if report_date else "Not available"
                ),
                "status": item.status,
                "score": round(total_score * 100)
            })

    return matches


# -----------------------------------------
# API - CHECK POSSIBLE DUPLICATE REPORTS
# -----------------------------------------

@app.route("/api/check-duplicate", methods=["POST"])
@login_required(role="user")
def api_check_duplicate():

    data = request.get_json(silent=True) or {}

    report_type = str(
        data.get("report_type", "")
    ).strip().lower()

    item_name = str(
        data.get("item_name", "")
    ).strip()

    category = str(
        data.get("category", "")
    ).strip()

    description = str(
        data.get("description", "")
    ).strip()

    location = str(
        data.get("location", "")
    ).strip()

    if report_type not in ("lost", "found"):

        return jsonify({
            "success": False,
            "message": "Invalid report type."
        }), 400

    if not all([
        item_name,
        category,
        description,
        location
    ]):

        return jsonify({
            "success": False,
            "message": "Complete the report fields first."
        }), 400

    matches = find_duplicate_reports(
        report_type,
        item_name,
        category,
        description,
        location
    )

    return jsonify({
        "success": True,
        "has_duplicates": bool(matches),
        "matches": matches
    })


# -----------------------------------------
# REPORT LOST / FOUND ITEM
# -----------------------------------------

@app.route("/report-item", methods=["GET", "POST"])
@login_required(role="user")
def report_item():

    if request.method == "POST":

        report_type = request.form.get(
            "report_type", ""
        ).strip().lower()

        item_name = request.form.get(
            "item_name", ""
        ).strip()

        category = request.form.get(
            "category", ""
        ).strip()

        description = request.form.get(
            "description", ""
        ).strip()

        location = request.form.get(
            "location", ""
        ).strip()

        report_date = request.form.get(
            "report_date", ""
        ).strip()

        if report_type not in ("lost", "found"):

            flash(
                "Please select a valid report type.",
                "error"
            )

            return redirect(url_for("report_item"))

        if not all([
            item_name,
            category,
            description,
            location,
            report_date
        ]):

            flash(
                "Please complete all required fields.",
                "error"
            )

            return redirect(url_for("report_item"))

        try:

            item_date = datetime.strptime(
                report_date,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            flash(
                "Please enter a valid date.",
                "error"
            )

            return redirect(url_for("report_item"))

        # Repeat duplicate detection on the server before saving.
        duplicate_matches = find_duplicate_reports(
            report_type,
            item_name,
            category,
            description,
            location
        )

        confirmation = request.form.get(
            "confirm_duplicates",
            ""
        )

        if duplicate_matches and confirmation != "yes":

            return render_template(
                "report_item.html",
                duplicate_matches=duplicate_matches,
                form_data=request.form
            )

        uploaded_images = request.files.getlist("images")

        if len(uploaded_images) > 5:

            flash(
                "You can upload a maximum of 5 images.",
                "error"
            )

            return redirect(url_for("report_item"))

        try:

            for image_file in uploaded_images:

                if image_file and image_file.filename:
                    validate_and_sanitize_image(image_file)

        except ValueError as error:

            flash(str(error), "error")

            return redirect(url_for("report_item"))

        new_item = Item(
            user_id=session["user_id"],
            item_name=item_name,
            category=category,
            description=description,
            location=location,
            date_lost=item_date if report_type == "lost" else None,
            date_found=item_date if report_type == "found" else None,
            report_type=report_type,
            status="Active"
        )

        saved_files = []

        try:

            db.session.add(new_item)
            db.session.flush()

            for image_file in uploaded_images:

                if image_file and image_file.filename:

                    unique_name, save_path = save_validated_image(
                        image_file
                    )

                    saved_files.append(save_path)

                    new_image = ItemImage(
                        item_id=new_item.id,
                        filename=unique_name
                    )

                    db.session.add(new_image)

            db.session.commit()

        except Exception:

            db.session.rollback()

            for file_path in saved_files:

                if os.path.exists(file_path):
                    os.remove(file_path)

            app.logger.exception(
                "Could not save item report"
            )

            flash(
                "Could not save your report. Please try again.",
                "error"
            )

            return redirect(url_for("report_item"))

        flash(
            "Your item report was submitted successfully!",
            "success"
        )

        return redirect(url_for("student_dashboard"))

    return render_template(
        "report_item.html",
        form_data={
            "report_type": request.args.get("report_type", "")
        },
        duplicate_matches=[]
    )
    # -----------------------------------------
# BROWSE ALL ITEMS
# -----------------------------------------

@app.route("/browse-items")
@login_required(role="user")
def browse_items():

    search = request.args.get(
        "search", ""
    ).strip()

    report_type = request.args.get(
        "type", "all"
    ).strip().lower()

    query = Item.query

    if report_type in ("lost", "found"):

        query = query.filter_by(
            report_type=report_type
        )

    else:
        report_type = "all"

    if search:

        search_term = f"%{search}%"

        query = query.filter(
            db.or_(
                Item.item_name.ilike(search_term),
                Item.description.ilike(search_term),
                Item.category.ilike(search_term),
                Item.location.ilike(search_term)
            )
        )

    items = query.order_by(
        Item.created_at.desc()
    ).all()

    return render_template(
        "browse_items.html",
        items=items,
        search=search,
        report_type=report_type
    )


# -----------------------------------------
# CLAIM ITEM
# -----------------------------------------

@app.route(
    "/claim-item/<int:item_id>",
    methods=["GET", "POST"]
)
@login_required(role="user")
def claim_item(item_id):

    item = db.session.get(
        Item,
        item_id
    )

    if item is None:

        flash(
            "The item could not be found.",
            "error"
        )

        return redirect(url_for("browse_items"))

    if (
        item.report_type != "found"
        or item.status != "Active"
    ):

        flash(
            "This item is not currently available for claiming.",
            "error"
        )

        return redirect(url_for("browse_items"))

    if item.user_id == session["user_id"]:

        flash(
            "You cannot claim an item you reported yourself.",
            "error"
        )

        return redirect(url_for("browse_items"))

    existing_claim = Claim.query.filter_by(
        item_id=item.id,
        user_id=session["user_id"]
    ).first()

    if existing_claim:

        flash(
            "You have already submitted a claim for this item.",
            "error"
        )

        return redirect(url_for("browse_items"))

    if request.method == "POST":

        message = request.form.get(
            "message", ""
        ).strip()

        image_file = request.files.get("image")

        if not message:

            flash(
                "Please provide details to verify your ownership.",
                "error"
            )

            return render_template(
                "claim_item.html",
                item=item
            )

        if len(message) > 2000:

            flash(
                "Your explanation must be 2000 characters or fewer.",
                "error"
            )

            return render_template(
                "claim_item.html",
                item=item
            )

        if image_file and image_file.filename:

            try:

                validate_and_sanitize_image(image_file)

            except ValueError as error:

                flash(str(error), "error")

                return render_template(
                    "claim_item.html",
                    item=item
                )

        saved_path = None

        try:

            new_claim = Claim(
                item_id=item.id,
                user_id=session["user_id"],
                message=message,
                status="Pending"
            )

            db.session.add(new_claim)
            db.session.flush()

            if image_file and image_file.filename:

                unique_name, saved_path = save_validated_image(
                    image_file
                )

                claim_image = ClaimImage(
                    claim_id=new_claim.id,
                    filename=unique_name
                )

                db.session.add(claim_image)

            db.session.commit()

        except Exception:

            db.session.rollback()

            if saved_path and os.path.exists(saved_path):
                os.remove(saved_path)

            app.logger.exception(
                "Could not submit claim"
            )

            flash(
                "Could not submit your claim. Please try again.",
                "error"
            )

            return render_template(
                "claim_item.html",
                item=item
            )

        flash(
            "Your claim has been submitted successfully.",
            "success"
        )

        return redirect(url_for("browse_items"))

    return render_template(
        "claim_item.html",
        item=item
    )


# -----------------------------------------
# STUDENT NOTIFICATIONS
# -----------------------------------------

@app.route("/notifications")
@login_required(role="user")
def notifications():

    user_notifications = Notification.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        Notification.created_at.desc()
    ).all()

    unread_count = Notification.query.filter_by(
        user_id=session["user_id"],
        is_read=False
    ).count()

    return render_template(
        "notifications.html",
        notifications=user_notifications,
        unread_count=unread_count
    )


# -----------------------------------------
# MARK NOTIFICATION AS READ
# -----------------------------------------

@app.route(
    "/notifications/<int:notification_id>/read",
    methods=["POST"]
)
@login_required(role="user")
def mark_notification_read(notification_id):

    notification = Notification.query.filter_by(
        id=notification_id,
        user_id=session["user_id"]
    ).first()

    if notification is None:

        flash(
            "Notification not found.",
            "error"
        )

        return redirect(url_for("notifications"))

    notification.is_read = True

    db.session.commit()

    flash(
        "Notification marked as read.",
        "success"
    )

    return_to = request.form.get(
        "return_to",
        "notifications"
    )

    if return_to == "dashboard":
        return redirect(url_for("student_dashboard"))

    return redirect(url_for("notifications"))


# -----------------------------------------
# ADMIN - MANAGE ITEMS
# -----------------------------------------

@app.route("/admin/items")
@login_required(role="admin")
def admin_items():

    items = Item.query.order_by(
        Item.created_at.desc()
    ).all()

    return render_template(
        "admin_items.html",
        items=items
    )


# -----------------------------------------
# ADMIN - MARK ITEM AS RESOLVED
# -----------------------------------------

@app.route(
    "/admin/items/<int:item_id>/resolve",
    methods=["POST"]
)
@login_required(role="admin")
def resolve_item(item_id):

    item = db.session.get(Item, item_id)

    if item is None:

        flash("Item report not found.", "error")
        return redirect(url_for("admin_items"))

    if item.status != "Active":

        flash(
            "Only active item reports can be marked as resolved.",
            "error"
        )

        return redirect(url_for("admin_items"))

    try:

        item.status = "Resolved"

        db.session.add(
            Notification(
                user_id=item.user_id,
                title="Item Resolved",
                message=(
                    f"Your report for '{item.item_name}' "
                    "has been marked as resolved by the administrator."
                ),
                is_read=False
            )
        )

        pending_claims = Claim.query.filter_by(
            item_id=item.id,
            status="Pending"
        ).all()

        for claim in pending_claims:

            claim.status = "Rejected"

            db.session.add(
                Notification(
                    user_id=claim.user_id,
                    claim_id=claim.id,
                    title="Claim Closed",
                    message=(
                        f"The report for '{item.item_name}' has been marked "
                        "as resolved. Your pending claim is no longer active."
                    ),
                    is_read=False
                )
            )

        db.session.commit()

        flash(
            f"'{item.item_name}' has been marked as resolved.",
            "success"
        )

    except Exception:

        db.session.rollback()

        app.logger.exception("Could not resolve item report")

        flash(
            "Could not mark the item as resolved. Please try again.",
            "error"
        )

    return redirect(url_for("admin_items"))


# -----------------------------------------
# MY CLAIMS
# -----------------------------------------

@app.route("/my-claims")
@login_required(role="user")
def my_claims():

    claims = Claim.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        Claim.created_at.desc()
    ).all()

    return render_template(
        "my_claims.html",
        claims=claims
    )
    # -----------------------------------------
# MY REPORTS
# -----------------------------------------

@app.route("/my-reports")
@login_required(role="user")
def my_reports():

    search = request.args.get(
        "search", ""
    ).strip()

    report_type = request.args.get(
        "type", "all"
    ).strip().lower()

    user_id = session["user_id"]

    query = Item.query.filter_by(
        user_id=user_id
    )

    if report_type in ("lost", "found"):

        query = query.filter_by(
            report_type=report_type
        )

    else:
        report_type = "all"

    if search:

        search_term = f"%{search}%"

        query = query.filter(
            db.or_(
                Item.item_name.ilike(search_term),
                Item.description.ilike(search_term),
                Item.category.ilike(search_term),
                Item.location.ilike(search_term)
            )
        )

    items = query.order_by(
        Item.created_at.desc()
    ).all()

    return render_template(
        "my_reports.html",
        items=items,
        search=search,
        report_type=report_type
    )


# -----------------------------------------
# EDIT ITEM REPORT
# -----------------------------------------

@app.route(
    "/edit-report/<int:item_id>",
    methods=["GET", "POST"]
)
@login_required(role="user")
def edit_report(item_id):

    item = Item.query.filter_by(
        id=item_id,
        user_id=session["user_id"]
    ).first()

    if item is None:

        flash(
            "Report not found or you are not authorized to edit it.",
            "error"
        )

        return redirect(url_for("my_reports"))

    if item.status != "Active":

        flash(
            "Only active reports can be edited.",
            "error"
        )

        return redirect(url_for("my_reports"))

    existing_claim = Claim.query.filter_by(
        item_id=item.id
    ).first()

    if existing_claim:

        flash(
            "This report cannot be edited because claims have already been submitted.",
            "error"
        )

        return redirect(url_for("my_reports"))

    if request.method == "POST":

        report_type = request.form.get(
            "report_type", ""
        ).strip().lower()

        item_name = request.form.get(
            "item_name", ""
        ).strip()

        category = request.form.get(
            "category", ""
        ).strip()

        description = request.form.get(
            "description", ""
        ).strip()

        location = request.form.get(
            "location", ""
        ).strip()

        report_date = request.form.get(
            "report_date", ""
        ).strip()

        if report_type not in ("lost", "found"):

            flash(
                "Please select a valid report type.",
                "error"
            )

            return redirect(
                url_for("edit_report", item_id=item.id)
            )

        if not all([
            item_name,
            category,
            description,
            location,
            report_date
        ]):

            flash(
                "Please complete all required fields.",
                "error"
            )

            return redirect(
                url_for("edit_report", item_id=item.id)
            )

        try:

            item_date = datetime.strptime(
                report_date,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            flash(
                "Please enter a valid date.",
                "error"
            )

            return redirect(
                url_for("edit_report", item_id=item.id)
            )

        remove_ids_raw = request.form.getlist(
            "remove_image_ids"
        )

        try:

            remove_ids = {
                int(image_id)
                for image_id in remove_ids_raw
            }

        except ValueError:

            flash(
                "Invalid image selection.",
                "error"
            )

            return redirect(
                url_for("edit_report", item_id=item.id)
            )

        existing_images = ItemImage.query.filter_by(
            item_id=item.id
        ).all()

        existing_image_ids = {
            image.id for image in existing_images
        }

        if not remove_ids.issubset(existing_image_ids):

            flash(
                "Invalid image selection.",
                "error"
            )

            return redirect(
                url_for("edit_report", item_id=item.id)
            )

        images_to_remove = [
            image for image in existing_images
            if image.id in remove_ids
        ]

        images_to_keep = [
            image for image in existing_images
            if image.id not in remove_ids
        ]

        uploaded_images = [
            image
            for image in request.files.getlist("images")
            if image and image.filename
        ]

        if len(images_to_keep) + len(uploaded_images) > 5:

            flash(
                "A report can have a maximum of 5 images. "
                "Remove an existing image before adding another.",
                "error"
            )

            return redirect(
                url_for("edit_report", item_id=item.id)
            )

        # Validate all new images before saving them.
        try:

            for image_file in uploaded_images:
                validate_and_sanitize_image(image_file)

        except ValueError as error:

            flash(str(error), "error")

            return redirect(
                url_for("edit_report", item_id=item.id)
            )

        saved_files = []

        old_file_paths = [
            os.path.join(
                app.config["UPLOAD_FOLDER"],
                os.path.basename(image.filename)
            )
            for image in images_to_remove
        ]

        try:

            item.item_name = item_name
            item.category = category
            item.description = description
            item.location = location
            item.report_type = report_type

            item.date_lost = (
                item_date if report_type == "lost" else None
            )

            item.date_found = (
                item_date if report_type == "found" else None
            )

            for image in images_to_remove:
                db.session.delete(image)

            for image_file in uploaded_images:

                unique_name, save_path = save_validated_image(
                    image_file
                )

                saved_files.append(save_path)

                db.session.add(
                    ItemImage(
                        item_id=item.id,
                        filename=unique_name
                    )
                )

            db.session.commit()

        except Exception:

            db.session.rollback()

            for file_path in saved_files:

                if os.path.exists(file_path):
                    os.remove(file_path)

            app.logger.exception(
                "Could not update item report"
            )

            flash(
                "Could not update your report. Please try again.",
                "error"
            )

            return redirect(
                url_for("edit_report", item_id=item.id)
            )

        # Delete removed image files only after the database commit.
        for file_path in old_file_paths:

            if os.path.isfile(file_path):

                try:
                    os.remove(file_path)

                except OSError:

                    app.logger.exception(
                        "Could not remove old report image: %s",
                        file_path
                    )

        flash(
            "Your report has been updated successfully.",
            "success"
        )

        return redirect(url_for("my_reports"))

    return render_template(
        "edit_item.html",
        item=item
    )


# -----------------------------------------
# DELETE ITEM REPORT
# -----------------------------------------

@app.route(
    "/delete-report/<int:item_id>",
    methods=["POST"]
)
@login_required(role="user")
def delete_report(item_id):

    item = Item.query.filter_by(
        id=item_id,
        user_id=session["user_id"]
    ).first()

    if item is None:

        flash(
            "Report not found or you are not authorized to delete it.",
            "error"
        )

        return redirect(url_for("my_reports"))

    existing_claim = Claim.query.filter_by(
        item_id=item.id
    ).first()

    if existing_claim:

        flash(
            "This report cannot be deleted because claims have been submitted for it.",
            "error"
        )

        return redirect(url_for("my_reports"))

    image_paths = [
        os.path.join(
            app.config["UPLOAD_FOLDER"],
            os.path.basename(image.filename)
        )
        for image in ItemImage.query.filter_by(
            item_id=item.id
        ).all()
    ]

    try:

        db.session.delete(item)
        db.session.commit()

    except Exception:

        db.session.rollback()

        app.logger.exception(
            "Could not delete item report"
        )

        flash(
            "Could not delete your report. Please try again.",
            "error"
        )

        return redirect(url_for("my_reports"))

    # Remove image files only after the database deletion succeeds.
    for file_path in image_paths:

        if os.path.isfile(file_path):

            try:
                os.remove(file_path)

            except OSError:

                app.logger.exception(
                    "Could not remove deleted report image: %s",
                    file_path
                )

    flash(
        "Your report has been deleted successfully.",
        "success"
    )

    return redirect(url_for("my_reports"))


# -----------------------------------------
# SERVE UPLOADED IMAGES
# -----------------------------------------

@app.route("/uploads/<path:filename>")
@login_required()
def uploaded_file(filename):

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename
    )


# -----------------------------------------
# APPLICATION START
# -----------------------------------------

if __name__ == "__main__":
    app.run(debug=True)