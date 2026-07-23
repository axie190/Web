"""
app.py
게시판 기능을 담당하는 Flask 앱입니다.

이 파일에서 하는 일은 크게 6가지입니다.
1) 게시글 목록 보여주기 + 검색(제목/내용/전체)
2) 글쓰기
3) 글 하나 자세히 보기 (들어올 때마다 조회수 올리기)
4) 글 수정하기
5) 글 삭제하기
6) 포트폴리오 메인 페이지(index.html)도 같이 열어주기

DB 관련해서는 과제 조건 때문에 이렇게 만들었습니다.
- sqlalchemy 같은 ORM은 쓰면 안 되니까, pymysql로 SQL 문장을 직접 써서 실행합니다.
- DB 비밀번호를 코드에 그대로 적으면 안 돼서, .env 파일에 따로 빼두고
  db.py에서 불러오게 했습니다 (자세한 내용은 db.py 참고).
"""
import os
import time
import uuid
from datetime import datetime

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from db import get_connection

app = Flask(__name__, static_url_path="/board/static")

# 예전에는 .env에 값이 없으면 "dev-only-fallback-key"라는 고정값으로 그냥 넘어갔는데,
# 이 값은 소스코드에 그대로 남아있어서 누구나 볼 수 있습니다. 세션은 이 키로 서명되니까,
# 키를 알면 로그인 세션(관리자 세션 포함)을 위조할 수 있습니다. 그래서 .env에 제대로 된
# 값이 없으면 조용히 넘어가지 않고 아예 서버가 안 뜨게 바꿨습니다.
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY가 .env에 설정되어 있지 않습니다. board/.env.example을 참고해서 값을 넣어주세요.")
app.secret_key = FLASK_SECRET_KEY


# 상대경로로 된 <script src="js/script.js">가 RPO(상대경로 조작)나 DOM Clobbering으로
# 이어질 수 있다는 지적을 받아서, 최소한의 CSP(Content-Security-Policy)를 붙였습니다.
# script-src를 'self'로 제한해두면, 페이지 경로가 어떻게 조작되더라도 다른 출처(예: 공격자
# 서버)에서 스크립트를 끌어오는 건 브라우저가 막아줍니다. 다만 view.html/members.html에
# onclick="..." 같은 인라인 스크립트를 이미 쓰고 있어서, 그것까지 막으면 페이지가 아예
# 동작을 안 해서 script-src에는 'unsafe-inline'을 같이 넣었습니다(인라인 스크립트를
# 전부 외부 .js 파일로 옮기면 이것도 뺄 수 있습니다). style-src/font-src는 구글 폰트를
# 쓰고 있어서 그 출처만 추가로 허용했습니다.
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com"
    )
    return response


# 로그인/글 비밀번호 확인을 무제한으로 시도할 수 있으면 비밀번호를 무차별 대입으로
# 맞출 수 있어서, 같은 대상으로 10번 틀리면 5분 동안 더 이상 시도할 수 없게 막습니다.
# Redis 같은 별도 저장소 없이, 그냥 딕셔너리 하나로 실패 횟수/마지막 실패 시각만
# 기억합니다. 그래서 서버(gunicorn worker)를 재시작하면 기록이 초기화되고, 워커가
# 여러 개면 워커마다 따로 셉니다 — 학교 과제 규모에서는 이 정도로 충분하다고 봤습니다.
LOGIN_ATTEMPT_LIMIT = 10
LOGIN_LOCKOUT_SECONDS = 5 * 60
_failed_attempts = {}


def register_failed_attempt(key):
    count, _ = _failed_attempts.get(key, (0, 0))
    _failed_attempts[key] = (count + 1, time.time())


def clear_failed_attempts(key):
    _failed_attempts.pop(key, None)


def is_locked_out(key):
    count, last_attempt_at = _failed_attempts.get(key, (0, 0))
    if count < LOGIN_ATTEMPT_LIMIT:
        return False
    if time.time() - last_attempt_at > LOGIN_LOCKOUT_SECONDS:
        # 잠긴 지 5분이 지났으면 기록을 지우고 다시 시도할 수 있게 해줍니다.
        _failed_attempts.pop(key, None)
        return False
    return True


# 첨부파일 저장 위치를 board/static이나 포트폴리오 폴더가 아니라 이 별도 폴더로 잡았습니다.
# static/이나 portfolio 폴더는 누구나 주소만 알면 바로 접근되는(웹에서 직접 서빙되는) 곳이라,
# 업로드 파일을 그대로 두면 악성 파일이 그 주소로 직접 실행/열람될 수 있습니다.
# uploads/는 어떤 라우트/static 설정으로도 직접 서빙하지 않고, 아래 download_attachment()
# 함수를 통해서만(DB에 저장된 정보로 파일을 찾아서) 내려주도록 만들었습니다.
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 업로드 요청 전체 크기 제한(파일 여러 개 합쳐서). 하나의 파일이 이보다 크면 개별 체크에서 걸러집니다.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10MB
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES * 5

# 업로드를 허용하는 확장자 화이트리스트입니다. .php, .jsp, .exe처럼 실행 가능한 확장자는
# 여기 없으니 자동으로 막힙니다 (금지 목록을 따로 만드는 대신, 허용 목록만 정의).
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "pdf"}

# 프로필 사진은 게시글 첨부와 다르게 PDF는 의미가 없어서 이미지 확장자만 허용합니다.
PROFILE_IMAGE_EXTENSIONS = ALLOWED_EXTENSIONS - {"pdf"}

# 확장자만으로는 사용자가 파일명을 속일 수 있어서(예: 악성코드에 .png만 붙이기),
# 실제 파일 내용 맨 앞 바이트(시그니처)를 직접 읽어서 진짜 타입을 확인합니다.
# 클라이언트가 폼에서 보내는 Content-Type은 브라우저/사용자가 얼마든지 조작할 수 있으므로 신뢰하지 않습니다.
def detect_upload_type(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"%PDF-"):
        return "pdf"
    return None


UPLOAD_MIME_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "pdf": "application/pdf",
}


def file_extension(filename):
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


# 업로드된 파일들을 검증만 하고 아직 디스크/DB에는 아무것도 쓰지 않습니다.
# (글 저장 전에 먼저 전부 검증해서, 파일 하나라도 문제 있으면 글 자체를 만들지 않기 위함입니다.)
# 문제가 있으면 ValueError(사용자에게 보여줄 메시지)를 발생시킵니다.
# allowed_extensions를 안 넘기면 게시글 첨부용 기본 화이트리스트(ALLOWED_EXTENSIONS)를 쓰고,
# 프로필 사진처럼 이미지만 받아야 하는 곳에서는 PROFILE_IMAGE_EXTENSIONS를 따로 넘겨서 씁니다.
def validate_uploads(files, allowed_extensions=None):
    if allowed_extensions is None:
        allowed_extensions = ALLOWED_EXTENSIONS
    allowed_label = "/".join(sorted(allowed_extensions))

    prepared = []
    for f in files:
        if not f or not f.filename:
            continue

        original_name = secure_filename(f.filename) or "file"

        ext_claimed = file_extension(original_name)
        if ext_claimed not in allowed_extensions:
            raise ValueError(f"'{original_name}': {allowed_label} 형식의 파일만 업로드할 수 있습니다.")

        data = f.read()
        if not data:
            continue
        if len(data) > MAX_UPLOAD_BYTES:
            raise ValueError(f"'{original_name}': 파일 하나당 최대 {MAX_UPLOAD_BYTES // (1024 * 1024)}MB까지 업로드할 수 있습니다.")

        # 확장자(claimed)와 별개로, 실제 내용을 읽어서 진짜 타입을 다시 확인합니다.
        # 저장할 때는 사용자가 준 확장자가 아니라 여기서 확인된 진짜 확장자를 씁니다.
        detected_ext = detect_upload_type(data)
        if detected_ext is None or detected_ext not in allowed_extensions:
            raise ValueError(f"'{original_name}': {allowed_label} 형식의 파일만 업로드할 수 있습니다.")

        prepared.append(
            {
                "original_name": original_name,
                "ext": detected_ext,
                "mimetype": UPLOAD_MIME_TYPES[detected_ext],
                "data": data,
            }
        )
    return prepared


# validate_uploads()로 검증이 끝난 파일 하나를 실제로 디스크에 씁니다. 파일명은 사용자가
# 입력한 그대로 저장하지 않고 uuid로 새로 만듭니다. 원래 파일명을 그대로 쓰면 경로 조작
# (../../etc/passwd 같은)이나 같은 이름 파일 덮어쓰기 문제가 생길 수 있기 때문입니다.
def save_uploaded_file(item):
    stored_name = f"{uuid.uuid4().hex}.{item['ext']}"
    with open(os.path.join(UPLOAD_DIR, stored_name), "wb") as out:
        out.write(item["data"])
    return stored_name


# 게시글 첨부파일은 여러 개일 수 있어서, 하나씩 저장하면서 attachments 테이블에도 같이 기록합니다.
# 원래 파일명은 다운로드할 때 보여주기 위해 DB(original_filename)에만 남겨둡니다.
def save_attachments(conn, post_id, prepared):
    with conn.cursor() as cur:
        for item in prepared:
            stored_name = save_uploaded_file(item)
            cur.execute(
                "INSERT INTO attachments (post_id, original_filename, stored_filename, content_type, size_bytes) "
                "VALUES (%s, %s, %s, %s, %s)",
                (post_id, item["original_name"], stored_name, item["mimetype"], len(item["data"])),
            )


# 글을 통째로 삭제하거나 첨부파일 하나를 삭제할 때, DB 행뿐 아니라 디스크의 실제 파일도 지웁니다.
# (posts 테이블에 ON DELETE CASCADE를 걸어놔서 DB 행은 자동으로 지워지지만, 디스크 파일은
#  직접 지워주지 않으면 uploads 폴더에 그대로 남습니다.)
def delete_attachment_files(stored_filenames):
    for stored_name in stored_filenames:
        path = os.path.join(UPLOAD_DIR, stored_name)
        if os.path.exists(path):
            os.remove(path)


# 게시판 주소는 전부 /board로 시작하게 만들었습니다.
# index.html 맨 위 메뉴에서 Board를 누르면 이 주소(/board)를 거쳐서
# /board/posts(목록)로 넘어갑니다.
@app.route("/board")
def board_home():
    return redirect(url_for("list_posts"))


# 게시글 목록 + 검색
# scope 값(all/title/content)에 따라 실행하는 쿼리를 다르게 나눴습니다.
# 검색어를 SQL 문장에 그냥 이어붙이면 SQL 인젝션 문제가 생길 수 있다고
# 배워서, 검색어는 항상 %s 자리표시자로 바인딩해서 넣었습니다.
@app.route("/board/posts")
def list_posts():
    query = request.args.get("q", "").strip()
    scope = request.args.get("scope", "all")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if not query:
                cur.execute("SELECT id, title, author, user_id, views, created_at, is_secret FROM posts ORDER BY id DESC")
            elif scope == "title":
                cur.execute(
                    "SELECT id, title, author, user_id, views, created_at, is_secret FROM posts WHERE title LIKE %s ORDER BY id DESC",
                    (f"%{query}%",),
                )
            elif scope == "content":
                # 비밀글의 내용은 검색 대상에서 제외합니다 (검색 결과로 비밀글 내용이 노출되면 안 되므로).
                cur.execute(
                    "SELECT id, title, author, user_id, views, created_at, is_secret FROM posts "
                    "WHERE is_secret = 0 AND content LIKE %s ORDER BY id DESC",
                    (f"%{query}%",),
                )
            else:
                # scope가 all이거나 이상한 값이 들어오면 제목/내용 둘 다 검색합니다.
                # 비밀글은 내용이 검색어와 일치해도 제목만 보여주고 내용을 노출하면 안 되니,
                # content LIKE 검색은 비밀글이 아닌 글로만 한정했습니다.
                cur.execute(
                    "SELECT id, title, author, user_id, views, created_at, is_secret FROM posts "
                    "WHERE title LIKE %s OR (is_secret = 0 AND content LIKE %s) ORDER BY id DESC",
                    (f"%{query}%", f"%{query}%"),
                )
            posts = cur.fetchall()
    finally:
        # 커넥션을 열었으면 끝나고 꼭 닫아줘야 해서 finally에 넣었습니다.
        conn.close()

    return render_template("list.html", posts=posts, query=query, scope=scope)


# 글쓰기 화면(GET)이랑 실제로 글 저장하는 처리(POST)를 한 함수에서 같이 합니다.
@app.route("/board/posts/new", methods=["GET", "POST"])
def new_post():
    if request.method == "GET":
        return render_template("write.html", post=None)

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    password = request.form.get("password", "")
    is_secret = 1 if request.form.get("is_secret") == "1" else 0

    # 로그인한 상태로 글을 쓰면 user_id를 같이 저장해서, 목록/상세보기에서 작성자명을
    # 누르면 이 회원의 프로필로 갈 수 있게 합니다. 비회원으로 쓰면 지금까지처럼 NULL입니다.
    user_id = session.get("user_id")

    # 로그인 안 했을 때는 지금까지처럼 작성자명을 자유롭게 입력받습니다(비어있으면 "익명").
    # 로그인했을 때는 write.html에서 작성자 입력칸 자체를 안 보여주고, 실제 작성자명은
    # 아래에서 회원가입할 때 등록한 이름으로 채웁니다(로그인 상태에서 입력값을 조작해도
    # 서버가 무시하고 항상 본인 계정 이름을 쓰게 하기 위함입니다).
    author = request.form.get("author", "").strip() or "익명"

    # 제목, 내용, 비밀번호 중 하나라도 비어있으면 저장하지 않고 다시 보여줍니다.
    # 비밀번호는 나중에 이 글을 수정/삭제할 때 본인 확인용으로, 비밀글이면 열람할 때도 씁니다.
    if not title or not content or not password:
        return render_template(
            "write.html",
            post={"title": title, "author": author, "content": content},
            error="제목, 내용, 비밀번호를 모두 입력해주세요.",
        )

    # 첨부파일은 DB에 글을 만들기 전에 먼저 전부 검증합니다. 파일 하나라도 허용되지 않는
    # 형식이면, 글 자체를 만들지 않고 에러만 보여줍니다 (파일 없는 글이 먼저 만들어지는 것 방지).
    try:
        prepared_files = validate_uploads(request.files.getlist("attachments"))
    except ValueError as e:
        return render_template(
            "write.html",
            post={"title": title, "author": author, "content": content},
            error=str(e),
        )

    # 비밀번호를 그대로 저장하면 DB가 털렸을 때 바로 보이니까, 해시로 바꿔서 저장합니다.
    # method 안 적고 그냥 generate_password_hash(password)만 쓰니까 실행할 때 에러가 나서,
    # 검색해보니 method="pbkdf2:sha256"을 붙이면 된다고 해서 이렇게 했습니다.
    password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    conn = get_connection()
    try:
        if user_id:
            with conn.cursor() as cur:
                cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
                member = cur.fetchone()
            author = member["name"] if member else "익명"

        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO posts (title, author, content, password_hash, is_secret, user_id) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (title, author, content, password_hash, is_secret, user_id),
            )
            new_id = cur.lastrowid  # 방금 저장한 글의 id. 상세페이지로 넘어갈 때 씁니다.

        save_attachments(conn, new_id, prepared_files)
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("view_post", post_id=new_id))


# 글 하나 자세히 보기. 들어올 때마다 조회수를 1씩 올려줍니다.
# 비밀글이면 이 세션에서 verify_password(action=view)로 비밀번호 확인이 끝나있어야
# unlocked가 True가 되고, 그래야 view.html이 내용/첨부파일을 화면에 그려줍니다.
@app.route("/board/posts/<int:post_id>")
def view_post(post_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE posts SET views = views + 1 WHERE id = %s", (post_id,))
            conn.commit()

            cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
            post = cur.fetchone()

            if post is None:
                abort(404)

            unlocked = not post["is_secret"] or bool(session.get(f"view_ok_{post_id}"))

            attachments = []
            author_profile = None
            if unlocked:
                cur.execute(
                    "SELECT id, original_filename, size_bytes FROM attachments WHERE post_id = %s ORDER BY id",
                    (post_id,),
                )
                attachments = cur.fetchall()

                # 회원이 쓴 글이면(post.user_id가 있으면), 화면 아래에 그 회원의 프로필
                # (이름/학교/프로필 이미지)을 같이 보여주기 위해 조회합니다.
                if post["user_id"]:
                    cur.execute(
                        "SELECT id, username, name, school, profile_image FROM users WHERE id = %s",
                        (post["user_id"],),
                    )
                    author_profile = cur.fetchone()
    finally:
        conn.close()

    return render_template(
        "view.html", post=post, unlocked=unlocked, attachments=attachments, author_profile=author_profile
    )


# 비밀번호 확인 전용 엔드포인트.
# 예전에는 비밀번호를 ?pw=로 주소에 붙이거나 화면의 hidden 값에 넣어뒀는데,
# 그러면 주소창/서버 로그/페이지 소스에 비밀번호가 그대로 남는다는 걸 알게 돼서
# (멘토님 리뷰로 지적받음) fetch로 서버에 잠깐 보내서 확인만 하고,
# 화면에는 비밀번호 자체가 아니라 "확인 완료"라는 표시만 세션에 남기는 방식으로 바꿨습니다.
@app.route("/board/posts/<int:post_id>/verify", methods=["POST"])
def verify_password(post_id):
    password = request.form.get("password", "")
    action = request.form.get("action", "")

    # 글 번호 단위로 실패 횟수를 셉니다. 이 글의 비밀번호를 계속 틀리면 잠깁니다.
    lockout_key = f"post_verify:{post_id}"
    if is_locked_out(lockout_key):
        return jsonify(ok=False, error="비밀번호를 너무 많이 실패했습니다. 5분 후 다시 시도해주세요.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM posts WHERE id = %s", (post_id,))
            post = cur.fetchone()

        if post is None:
            return jsonify(ok=False, error="글을 찾을 수 없습니다.")

        if not check_password_hash(post["password_hash"], password):
            register_failed_attempt(lockout_key)
            return jsonify(ok=False, error="비밀번호가 일치하지 않습니다.")

        clear_failed_attempts(lockout_key)

        if action == "delete":
            # posts에 ON DELETE CASCADE가 걸려있어 DB의 attachments 행은 자동으로 지워지지만,
            # 디스크에 남아있는 실제 파일은 따로 지워야 해서 미리 파일명을 읽어둡니다.
            with conn.cursor() as cur:
                cur.execute("SELECT stored_filename FROM attachments WHERE post_id = %s", (post_id,))
                stored_filenames = [row["stored_filename"] for row in cur.fetchall()]
                cur.execute("DELETE FROM posts WHERE id = %s", (post_id,))
            conn.commit()
            delete_attachment_files(stored_filenames)
            return jsonify(ok=True, redirect=url_for("list_posts"))

        if action == "view":
            # 비밀글 열람 확인. 이 세션에서 이 글 번호는 확인이 끝났다는 표시만 남기고,
            # 실제 내용은 view_post()가 이 표시를 보고 다시 렌더링할 때 보여줍니다.
            session[f"view_ok_{post_id}"] = True
            return jsonify(ok=True, redirect=url_for("view_post", post_id=post_id))

        # action == "edit": 세션에 "이 글 번호는 비밀번호 확인 끝남" 표시만 남깁니다.
        # 세션은 서버가 쿠키에 서명해서 관리하는 거라, 브라우저 주소나 페이지 소스에는
        # 아무것도 안 남습니다.
        session[f"edit_ok_{post_id}"] = True
        return jsonify(ok=True, redirect=url_for("edit_post", post_id=post_id))
    finally:
        conn.close()


# 글 수정. GET이면 기존 글 내용을 폼에 채워서 보여주고, POST면 실제로 수정합니다.
# 두 경우 다 verify_password에서 세션에 남겨둔 인증 표시가 있어야만 통과됩니다.
@app.route("/board/posts/<int:post_id>/edit", methods=["GET", "POST"])
def edit_post(post_id):
    if not session.get(f"edit_ok_{post_id}"):
        flash("비밀번호 확인이 필요합니다.")
        return redirect(url_for("view_post", post_id=post_id))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
            post = cur.fetchone()

            if post is None:
                abort(404)

            cur.execute(
                "SELECT id, original_filename, size_bytes FROM attachments WHERE post_id = %s ORDER BY id",
                (post_id,),
            )
            attachments = cur.fetchall()

        if request.method == "GET":
            return render_template("write.html", post=post, editing=True, attachments=attachments)

        title = request.form.get("title", "").strip()
        author = request.form.get("author", "").strip() or "익명"
        content = request.form.get("content", "").strip()

        if not title or not content:
            return render_template(
                "write.html",
                post={"id": post_id, "title": title, "author": author, "content": content},
                editing=True,
                attachments=attachments,
                error="제목과 내용을 모두 입력해주세요.",
            )

        try:
            prepared_files = validate_uploads(request.files.getlist("attachments"))
        except ValueError as e:
            return render_template(
                "write.html",
                post={"id": post_id, "title": title, "author": author, "content": content},
                editing=True,
                attachments=attachments,
                error=str(e),
            )

        # 체크된 기존 첨부파일은 삭제합니다. post_id로 한 번 더 범위를 좁혀서, 다른 글의
        # 첨부파일 id를 넣어도 지워지지 않게 했습니다.
        delete_ids = [int(v) for v in request.form.getlist("delete_attachment") if v.isdigit()]
        removed_filenames = []
        if delete_ids:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT stored_filename FROM attachments WHERE post_id = %s AND id IN %s",
                    (post_id, tuple(delete_ids)),
                )
                removed_filenames = [row["stored_filename"] for row in cur.fetchall()]
                cur.execute(
                    "DELETE FROM attachments WHERE post_id = %s AND id IN %s",
                    (post_id, tuple(delete_ids)),
                )

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE posts SET title = %s, author = %s, content = %s WHERE id = %s",
                (title, author, content, post_id),
            )

        save_attachments(conn, post_id, prepared_files)
        conn.commit()
        delete_attachment_files(removed_filenames)
        session.pop(f"edit_ok_{post_id}", None)  # 한 번 확인한 건 다시 못 쓰게 지웁니다.
    finally:
        conn.close()

    return redirect(url_for("view_post", post_id=post_id))


# 첨부파일 다운로드. uploads/ 폴더는 직접 서빙되지 않으므로, 이 라우트를 거쳐야만
# 파일을 받을 수 있습니다. attachment_id를 post_id 아래로 두고 두 값을 같이 검사해서,
# 다른 글의 첨부파일 id를 넣어 접근하는 것도 막았습니다.
# 글이 비밀글이면, 본문과 마찬가지로 세션에 비밀번호 확인 표시가 있어야만 다운로드할 수 있습니다.
@app.route("/board/posts/<int:post_id>/attachments/<int:attachment_id>")
def download_attachment(post_id, attachment_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT is_secret FROM posts WHERE id = %s", (post_id,))
            post = cur.fetchone()
            if post is None:
                abort(404)
            if post["is_secret"] and not session.get(f"view_ok_{post_id}"):
                abort(403)

            cur.execute(
                "SELECT * FROM attachments WHERE id = %s AND post_id = %s",
                (attachment_id, post_id),
            )
            attachment = cur.fetchone()
    finally:
        conn.close()

    if attachment is None:
        abort(404)

    # send_from_directory가 stored_filename에 경로 조작(../ 등)이 섞여 있는지도 같이 확인해줍니다.
    # as_attachment=True로 다운로드 처리해서, 브라우저가 파일을 실행하거나 화면에 바로 열지 않고
    # 항상 저장 대화상자로 받도록 강제합니다.
    return send_from_directory(
        UPLOAD_DIR,
        attachment["stored_filename"],
        as_attachment=True,
        download_name=attachment["original_filename"],
        mimetype=attachment["content_type"],
    )


# 업로드 용량 제한(MAX_CONTENT_LENGTH)을 넘으면 flask가 413 에러를 내는데, 그냥 두면
# 에러 페이지만 뜨고 무슨 상황인지 알기 어려워서 안내 메시지를 붙여 글쓰기/수정 화면으로 돌려보냅니다.
@app.errorhandler(413)
def handle_file_too_large(e):
    flash(f"첨부파일 용량이 너무 큽니다. (최대 {MAX_UPLOAD_BYTES // (1024 * 1024)}MB)")
    return redirect(request.referrer or url_for("list_posts"))


# 여기서부터는 회원가입/로그인/프로필 기능입니다. 지금까지 게시글은 회원가입 없이
# 작성자명 + 글마다 다른 비밀번호로 관리했는데, 그거랑은 별개로 로그인 계정을 만들어서
# 이름/학교/프로필 이미지를 등록해두고 "내 프로필" 페이지로 보여주는 기능입니다.
# 로그인 여부는 session["user_id"]가 있는지로 확인합니다.
@app.route("/board/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")
    name = request.form.get("name", "").strip()
    school = request.form.get("school", "").strip()
    birth_date_raw = request.form.get("birth_date", "").strip()
    gender = request.form.get("gender", "").strip() or None
    nationality = request.form.get("nationality", "").strip()

    form_values = {
        "username": username,
        "name": name,
        "school": school,
        "birth_date": birth_date_raw,
        "gender": gender,
        "nationality": nationality,
    }

    if not username or not password or not name or not school or not birth_date_raw or not nationality:
        return render_template(
            "register.html", error="아이디, 비밀번호, 이름, 학교, 생년월일, 국적을 모두 입력해주세요.", **form_values
        )

    if password != password_confirm:
        return render_template("register.html", error="비밀번호가 서로 일치하지 않습니다.", **form_values)

    # <input type="date">는 "YYYY-MM-DD" 형식으로 오는데, 혹시 다른 값이 억지로 넘어와도
    # DB에 이상한 값이 들어가지 않게 여기서 한 번 더 실제 날짜인지 확인합니다.
    try:
        birth_date = datetime.strptime(birth_date_raw, "%Y-%m-%d").date()
    except ValueError:
        return render_template("register.html", error="생년월일 형식이 올바르지 않습니다.", **form_values)

    try:
        prepared_files = validate_uploads(request.files.getlist("profile_image"), allowed_extensions=PROFILE_IMAGE_EXTENSIONS)
    except ValueError as e:
        return render_template("register.html", error=str(e), **form_values)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 아이디는 중복되면 안 되니까, 저장하기 전에 이미 쓰는 사람이 있는지 먼저 확인합니다.
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone() is not None:
                return render_template(
                    "register.html",
                    error="이미 사용 중인 아이디입니다.",
                    name=name,
                    school=school,
                    birth_date=birth_date_raw,
                    gender=gender,
                    nationality=nationality,
                )

        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        profile_image = save_uploaded_file(prepared_files[0]) if prepared_files else None

        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, name, school, birth_date, gender, nationality, profile_image) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (username, password_hash, name, school, birth_date, gender, nationality, profile_image),
            )
            new_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    # 회원가입하자마자 바로 로그인 상태로 만들어서 게시판 목록으로 이동시킵니다.
    # 회원가입으로는 관리자가 될 수 없어서 is_admin은 항상 False로 시작합니다.
    session["user_id"] = new_id
    session["username"] = username
    session["is_admin"] = False
    return redirect(url_for("list_posts"))


@app.route("/board/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # 아이디 단위로 실패 횟수를 세서, 같은 계정을 노리고 비밀번호를 계속 바꿔가며
    # 시도하는 걸 막습니다 (IP를 바꿔가며 시도해도 아이디는 그대로니까 걸립니다).
    lockout_key = f"login:{username}"
    if is_locked_out(lockout_key):
        return render_template(
            "login.html", error="로그인을 너무 많이 실패했습니다. 5분 후 다시 시도해주세요.", username=username
        )

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
    finally:
        conn.close()

    # user가 None이면 check_password_hash를 실행하지 않고(or의 앞쪽에서 바로 멈춤) 넘어갑니다.
    if user is None or not check_password_hash(user["password_hash"], password):
        register_failed_attempt(lockout_key)
        return render_template("login.html", error="아이디 또는 비밀번호가 일치하지 않습니다.", username=username)

    clear_failed_attempts(lockout_key)
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["is_admin"] = bool(user["is_admin"])
    return redirect(url_for("list_posts"))


@app.route("/board/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    session.pop("is_admin", None)
    return redirect(url_for("list_posts"))


# "내 프로필" 메뉴는 이 주소로 들어오는데, 실제 화면은 view_profile()이 그리는 것과 같아서
# 내 id로 view_profile로 다시 보내줍니다.
@app.route("/board/profile")
def my_profile():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    return redirect(url_for("view_profile", user_id=session["user_id"]))


# 회원목록은 아무 회원이나 보면 안 되고 관리자만 볼 수 있어야 해서, session["is_admin"]을
# 확인합니다. (개별 회원 프로필 보기(view_profile)는 그대로 누구나 볼 수 있습니다.)
@app.route("/board/users")
def list_users():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("관리자만 볼 수 있는 페이지입니다.")
        return redirect(url_for("list_posts"))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, name, school FROM users ORDER BY id")
            users = cur.fetchall()
    finally:
        conn.close()

    return render_template("members.html", users=users)


# 회원목록에서 관리자가 회원 계정을 삭제할 때 씁니다. list_users와 마찬가지로 관리자만
# 할 수 있고, 실수로 본인 계정을 지우는 일이 없도록 본인 id는 여기서 막아둡니다.
# 이 회원이 쓴 글은 삭제하지 않고 그대로 두는데, posts.user_id에 ON DELETE SET NULL을
# 걸어놔서 회원을 지우면 그 글들의 user_id만 자동으로 NULL이 되고(=프로필 링크가 사라짐)
# 글 자체(제목/내용/작성자명)는 그대로 남습니다.
@app.route("/board/users/<int:user_id>/delete", methods=["POST"])
def delete_member(user_id):
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("관리자만 할 수 있는 작업입니다.")
        return redirect(url_for("list_posts"))
    if user_id == session.get("user_id"):
        flash("본인 계정은 회원목록에서 삭제할 수 없습니다.")
        return redirect(url_for("list_users"))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
            member = cur.fetchone()
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
    finally:
        conn.close()

    if member and member["profile_image"]:
        delete_attachment_files([member["profile_image"]])

    return redirect(url_for("list_users"))


# 회원 프로필 보기. 로그인 없이도 누구나 들어올 수는 있지만, 그 회원이 프로필을
# 비공개(is_profile_public=0)로 해뒀으면 본인/관리자가 아닌 사람에게는 상세 정보를
# 안 보여주고 "비공개 프로필입니다" 안내만 보여줍니다 (can_view로 구분).
@app.route("/board/users/<int:user_id>")
def view_profile(user_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, name, school, birth_date, gender, nationality, "
                "profile_image, is_profile_public FROM users WHERE id = %s",
                (user_id,),
            )
            profile_user = cur.fetchone()
    finally:
        conn.close()

    if profile_user is None:
        abort(404)

    is_owner = profile_user["id"] == session.get("user_id")
    can_view = is_owner or session.get("is_admin") or bool(profile_user["is_profile_public"])
    return render_template("profile.html", profile_user=profile_user, is_owner=is_owner, can_view=can_view)


@app.route("/board/profile/edit", methods=["GET", "POST"])
def edit_profile():
    if not session.get("user_id"):
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
            user = cur.fetchone()

        if request.method == "GET":
            return render_template("profile_edit.html", user=user)

        name = request.form.get("name", "").strip()
        school = request.form.get("school", "").strip()
        birth_date_raw = request.form.get("birth_date", "").strip()
        gender = request.form.get("gender", "").strip() or None
        nationality = request.form.get("nationality", "").strip()
        is_profile_public = 1 if request.form.get("is_profile_public") == "1" else 0
        new_password = request.form.get("password", "")

        if not name or not school or not birth_date_raw or not nationality:
            return render_template(
                "profile_edit.html", user=user, error="이름, 학교, 생년월일, 국적을 모두 입력해주세요."
            )

        try:
            birth_date = datetime.strptime(birth_date_raw, "%Y-%m-%d").date()
        except ValueError:
            return render_template("profile_edit.html", user=user, error="생년월일 형식이 올바르지 않습니다.")

        try:
            prepared_files = validate_uploads(
                request.files.getlist("profile_image"), allowed_extensions=PROFILE_IMAGE_EXTENSIONS
            )
        except ValueError as e:
            return render_template("profile_edit.html", user=user, error=str(e))

        # 새 이미지를 올렸을 때만 파일을 바꾸고, 안 올렸으면 기존 이미지를 그대로 둡니다.
        old_profile_image = user["profile_image"]
        new_profile_image = save_uploaded_file(prepared_files[0]) if prepared_files else old_profile_image

        with conn.cursor() as cur:
            if new_password:
                password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
                cur.execute(
                    "UPDATE users SET name = %s, school = %s, birth_date = %s, gender = %s, nationality = %s, "
                    "is_profile_public = %s, profile_image = %s, password_hash = %s WHERE id = %s",
                    (
                        name, school, birth_date, gender, nationality,
                        is_profile_public, new_profile_image, password_hash, session["user_id"],
                    ),
                )
            else:
                cur.execute(
                    "UPDATE users SET name = %s, school = %s, birth_date = %s, gender = %s, nationality = %s, "
                    "is_profile_public = %s, profile_image = %s WHERE id = %s",
                    (name, school, birth_date, gender, nationality, is_profile_public, new_profile_image, session["user_id"]),
                )
        conn.commit()

        # 이미지를 새로 올렸으면, 더 이상 안 쓰는 예전 이미지 파일은 디스크에서 지워줍니다.
        if prepared_files and old_profile_image:
            delete_attachment_files([old_profile_image])
    finally:
        conn.close()

    return redirect(url_for("view_profile", user_id=session["user_id"]))


# 프로필 이미지는 첨부파일 다운로드와 다르게, <img> 태그로 화면에 바로 보여줘야 해서
# as_attachment를 안 씁니다 (기본값 False라 브라우저가 파일을 그대로 렌더링합니다).
@app.route("/board/profile-image/<int:user_id>")
def profile_image(user_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
    finally:
        conn.close()

    if row is None or row["profile_image"] is None:
        abort(404)

    ext = file_extension(row["profile_image"])
    mimetype = UPLOAD_MIME_TYPES.get(ext, "application/octet-stream")
    return send_from_directory(UPLOAD_DIR, row["profile_image"], mimetype=mimetype)


# 여기서부터는 게시판이 아니라, 포트폴리오 메인 페이지를 같이 열어주기 위한 부분입니다.
# index.html을 그냥 더블클릭해서 열면(file://) 상단의 Board 메뉴가 /board/posts라는
# 절대경로를 못 찾아서 눌러도 반응이 없었습니다. 그래서 Flask가 포트폴리오 파일까지
# 같이 서빙하게 만들어서, http://localhost:5050/ 하나로 포트폴리오 + 게시판을
# 전부 확인할 수 있게 했습니다.
PORTFOLIO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


@app.route("/")
def portfolio_home():
    return send_from_directory(PORTFOLIO_DIR, "index.html")


@app.route("/css/<path:filename>")
def portfolio_css(filename):
    return send_from_directory(os.path.join(PORTFOLIO_DIR, "css"), filename)


@app.route("/js/<path:filename>")
def portfolio_js(filename):
    return send_from_directory(os.path.join(PORTFOLIO_DIR, "js"), filename)


@app.route("/images/<path:filename>")
def portfolio_images(filename):
    return send_from_directory(os.path.join(PORTFOLIO_DIR, "images"), filename)


if __name__ == "__main__":
    # host를 0.0.0.0으로 열어둬야 같은 네트워크에 있는 다른 기기나,
    # 나중에 서버에 올렸을 때 외부에서도 접속할 수 있습니다.
    # debug=True를 그냥 박아두면, 나중에 실수로 gunicorn 대신 이 파일을 직접 실행하는
    # 배포 방식으로 바뀔 경우 Werkzeug 디버거(임의 코드 실행 가능)가 그대로 인터넷에
    # 노출될 수 있습니다. 그래서 로컬에서만 FLASK_DEBUG=1로 켜서 쓰고, 기본값은 꺼둡니다.
    app.run(host="0.0.0.0", port=5050, debug=os.environ.get("FLASK_DEBUG") == "1")
