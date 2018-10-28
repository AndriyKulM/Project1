import os
import requests
from functools import wraps

from flask import Flask, session, flash, redirect, render_template, request, url_for, jsonify
from flask_session import Session
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker


app = Flask(__name__)

# ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine("postgres://rxmdiqvyzxcukv:5210e1bc687a55a64e8de612081284c289f55e7ef8e0f9224e217962f8228936@ec2-54-221-210-97.compute-1.amazonaws.com:5432/de2n0btvhoke0g")
db = scoped_session(sessionmaker(bind=engine))

API_KEY = "XkdgeWZGB0EiD8mXemTqTw"


def apology(top="", bottom=""):
    """Renders message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=escape(top), bottom=escape(bottom))


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.11/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
@login_required
def index():

    return render_template("index.html")


@app.route("/search", methods=["POST"])
@login_required
def search():
    """Пошук книги по ISBN, назві або автору"""

    if request.method == "POST":
        # Перевіряємо, чи не пусте поле у формі
        if request.form.get("search") == "":
            return apology("must provide isbn or title or author")

        else:
            # Вибираємо значення полів isbn, title, author з таблиці books, де вони схожі на те, що ввів user у поле search пошукової форми
            searchedbooks = db.execute("""SELECT isbn, title, author FROM books
                                          WHERE isbn ILIKE :query OR title ILIKE :query OR author ILIKE :query 
                                        """, {"query": '%' + request.form.get("search") + '%'}).fetchall()

            if searchedbooks is None:                                      # якщо в змінній searchedbooks нічого немає
                return apology("no books matched")                                              # то повертаємо помилку

            return render_template("searched.html", searchedbooks=searchedbooks)

    else:

        return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user."""

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Перевіряємо, чи не пусті поля username, password і confirm-password в формі
        # ensure username was submitted
        if request.form.get("username") == "":
            return apology("must provide username")

        # ensure password was submitted
        elif request.form.get("password") == "":
            return apology("must provide password")

        # ensure confirm-password was submitted
        elif request.form.get("confirm-password") == "":
            return apology("must provide confirm-password")

        elif request.form.get("password") != request.form.get(
                "confirm-password"):                                # і чи співпадають поля password і confirm-password
            return apology("your passwords don't match")            # якщо ні - виводимо відповідні помилки.

        # query database for username
        # Вибираємо з таблиці users користувача з логіном,
        rows = db.execute("SELECT * FROM users WHERE username = :username", {"username": request.form.get("username")}).fetchone()

        # який введений в полі username
        if rows is None:                                                    # Якщо користувача з таким логіном не існує

            hash_password = pwd_context.hash(request.form.get("password"))                 # то зашифровуємо його пароль

            # і заносимо даного користувача в таблицю users (його логін і хешований пароль)

            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", {"username": request.form.get("username"), "hash": hash_password})

            db.commit()

            ins_rows = db.execute("SELECT * FROM users WHERE username = :username", {"username": request.form.get("username")}).fetchone()

            if ins_rows is None:
                return apology("Account creation failed")
            else:

                session["user_id"] = ins_rows["id"]         # Зберігаємо id user в сесії

                flash('You were successfully registered')  # Виводимо повідомлення користувачу, що він успішно зареєстрований.

                # redirect user to home page
                return redirect(url_for("index"))  # Перенаправляємо його на сторінку з пошуком - index.

        else:

            return apology("username already exists")  # Інакше виводимо помилку - користувач з таким логіном вже існує.

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", {"username": request.form.get("username")}).fetchone()

        # ensure username exists and password is correct
        if rows is None or not pwd_context.verify(request.form.get("password"), rows["hash"]):
            return apology("invalid username and/or password")

        # remember which user has logged in
        session["user_id"] = rows["id"]

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out."""

    # forget any user_id
    session.clear()

    # redirect user to login form
    return redirect(url_for("login"))


@app.route("/book_details/<isbn>", methods=["POST", "GET"])
def book_details(isbn):
    """Отримування детальніших даних для вибраної книги."""

    book_rows = db.execute("SELECT * FROM books WHERE isbn = :isbn", {"isbn": isbn}).fetchone()

    # Формуємо Api-запит до сайту Goodreads по ISBN та отримані дані у json-форматі переводимо у тип - словник
    res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": API_KEY, "isbns": isbn})
    goodreads_data = res.json()
    book_data = goodreads_data["books"][0]

    # Отримуємо з нашої бази даних всі дані, які стосуються review, об'єднавши таблиці по Foreign Key
    query = "SELECT users.id, users.username, books.title, reviews.rating, reviews.review FROM reviews JOIN books ON reviews.isbn_book = books.isbn JOIN users ON reviews.id = users.id"
    reviews_data = db.execute(query, {"isbn": isbn}).fetchall()

    # Перевіряємо, чи залишав відгук на сайті цей користувач
    have_user_review = False
    for review in reviews_data:
        print(review["review"])
        if review["id"] == session["user_id"]:
            have_user_review = True
    print(have_user_review)

    if request.method == "POST":
        if not have_user_review:                                    # Якщо не залишав - забираємо дані з форми
            review = request.form.get("review")                     # і добавляємо їх в таблицю reviews
            rating = request.form.get("rating")
            query = "INSERT INTO reviews(review, rating, id, isbn_book) VALUES (:review, :rating, :id, :isbn_book)"
            param = {"review":review, "rating":rating, "id":session["user_id"], "isbn_book": isbn}
            db.execute(query, param)
            db.commit()
    return render_template('book_details.html', book_rows = book_rows, book_data = book_data, reviews_data = reviews_data, have_user_review = have_user_review)


@app.route("/api/<string:isbn>")
def book_api(isbn):
    """This API return details about a single book in json format."""

    book_in_db = db.execute("SELECT * FROM books WHERE isbn = :isbn", {"isbn": isbn}).fetchone()

    if book_in_db is None:
        return jsonify({"error": "Invalid isbn"}), 422

    review_count = db.execute("SELECT COUNT(*) FROM reviews WHERE isbn_book = :isbn", {"isbn": isbn}).first()
    average_score_obj = db.execute("SELECT ROUND(AVG(rating::DECIMAL),2) FROM reviews WHERE isbn_book = :isbn", {"isbn": isbn}).first()

    if average_score_obj[0] is not None:
                    average_score = average_score_obj[0]
    else: average_score = 0

    return jsonify({
                    "title": book_in_db["title"],
                    "author": book_in_db["author"],
                    "year": book_in_db["year"],
                    "isbn": book_in_db["isbn"],
                    "review_count": review_count[0],
                    "average_score": average_score
                    })