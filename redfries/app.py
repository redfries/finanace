import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT symbol, SUM(shares) AS share FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)

    # for getting (DYNAMIC) current price, name and total from current price
    # pushing current price, name and total to trans dict.
    for row in transactions:
        row['name'] = lookup(row['symbol'])['name']
        row['price'] = usd(round(lookup(row['symbol'])['price'], 2))
        row['total'] = round(lookup(row['symbol'])['price'] * row['share'], 2)

    # total value of stocks and cash
    investment_total = 0

    for row in transactions:
        investment_total += row['total']

    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = round(float(cash_db[0]["cash"]), 2)
    total = usd(round(investment_total + cash, 2))

    for row in transactions:
        row['total'] = usd(row['total'])

    return render_template("index.html", transactions=transactions, cash=usd(cash), total=total)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Account Details"""

    user_id = session["user_id"]
    user = db.execute("SELECT username, cash FROM users WHERE id = ?", user_id)
    name = user[0]["username"]
    cash = user[0]["cash"]

    username = request.form.get("username")

    if request.method == "GET":
        return render_template("account.html", name=name, cash=usd(cash))
    else:
        if not username:
            return apology("Missing User Name")

        row = db.execute('SELECT username FROM users WHERE username = ?', username,)

        if row:
            return apology("UserName Exists")
        else:
            db.execute("UPDATE users SET username = ? WHERE id = ?", username, user_id)

    # Forget any user_id
    session.clear()

    flash("LOGIN AGAIN WITH NEW USERNAME")
    # Redirect user to login form
    return render_template("login.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        num_shares = request.form.get("shares")
        share = lookup(symbol.upper())

        # checking for errors
        if not symbol:
            return apology("Missing Symbol")
        if not num_shares:
            return apology("Missing Shares")
        if not num_shares.isdigit():
            return apology("You cannot purchase partial shares.")
        if int(num_shares) < 0:
            return apology("Missing Shares")
        else:
            shares_bought = int(num_shares)

        if share == None:
            return apology("Invalid Symbol")

        price_of_stocks = int(num_shares) * share["price"]  # determining the total price of stocks

        user_id = session["user_id"]
        # getting cash available from users
        cash_db = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        cash_bl = cash_db[0]["cash"]

        if cash_bl < price_of_stocks:
            return apology("You are not rich")

        cash_upd = cash_bl - price_of_stocks
        # update this new cash to db
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_upd, user_id)

        date = datetime.datetime.now()
        # if all values are good then give it to transaction table
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, date) VALUES(?, ?, ?, ?, ?, ?)",
                   user_id, share["symbol"], share["name"], shares_bought, share["price"], date)

        flash("Bought!")

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT symbol, shares, price, date FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing Symbol")

        # Storing the lookup in res
        res = lookup(symbol.upper())

        if res == None:
            return apology("Invalid Symbol")

        # If symbol is good
        return render_template("quotation.html", name=res["name"], price=usd(res["price"]), symbol=res["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any userid
    session.clear()

    # as user submits throug post
    if request.method == "POST":

        user_name = request.form.get("username")

        # Ensure username is submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password is submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        if not request.form.get("confirmation"):
            return apology("must provide password", 400)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password should match", 400)

        # Hashing the password
        hash = generate_password_hash(request.form.get("password"))

        # Remember user into database
        try:
            result = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", user_name, hash)
        except:
            return apology("username exists")

        session["user_id"] = result

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]

    if request.method == "GET":

        symbol = db.execute("SELECT DISTINCT(symbol) FROM transactions WHERE user_id = ?", user_id)

        return render_template("sell.html", symbol=symbol)
    else:
        user_id = session["user_id"]

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # checking for errors
        if not symbol:
            return apology("Missing Symbol")

        share = lookup(symbol.upper())["name"]
        if not shares:
            return apology("Missing Shares")

        if int(shares) <= 0:
            return apology("Missing Shares")
        else:
            shares = int(shares)

        if share == None:
            return apology("Invalid Symbol")

        # if shares selling is more than the user have
        trans = db.execute(
            "SELECT symbol, SUM(shares) AS shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol.upper())
        avi_shares = trans[0]["shares"]

        if avi_shares < shares:
            return apology("No No..")

        # Now sell
        # get the cp of share and amount of those
        cp_share = lookup(symbol.upper())["price"]
        amount = round(cp_share * shares, 2)

        # getting cash available from users
        cash_db = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        cash_bl = cash_db[0]["cash"]

        cash_upd = cash_bl + amount
        # update this new cash to db
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_upd, user_id)

        date = datetime.datetime.now()
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price, date) VALUES(?, ?, ?, ?, ?, ?)",
                   user_id, symbol, share, -shares, cp_share, date)

        flash("Sold!")

        return redirect("/")

