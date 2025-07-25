import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///list.db")


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
    """Show todo list"""
    user_id = session["user_id"]
    tasks = db.execute("SELECT id, task, note, due FROM lists WHERE user_id = ? AND status = 'active' ORDER BY due ASC", user_id)
    return render_template("index.html", tasks=tasks)



@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """add todo list"""
    if request.method == "POST":
        task = request.form.get("task")
        due = request.form.get("due")
        note = request.form.get("note")
        user_id = session["user_id"]

        if not task:
            return apology("Fields should not be empty")
        try:
            db.execute("INSERT INTO lists (user_id, task, note, due) VALUES (?, ?, ?, ?)",
                       session["user_id"], task, note, due)
            flash("Task added successfully!", "success")
            return redirect("/")

        except Exception as e:
            print(f"Database insertion error: {e}")
            return render_template("add.html", error_message=f"An error occurred: {e}")

    else:
        return render_template("add.html")




@app.route("/done")
@login_required
def done():
    """Show finished todo list"""
    user_id = session["user_id"]
    done_tasks = db.execute("SELECT id, task, note, due, timestamp FROM lists WHERE user_id = ? AND status = 'done' ORDER BY timestamp DESC", user_id)
    return render_template("done.html", done_tasks=done_tasks)

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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "POST":
        task_id = request.form.get("task_id") # Get the task ID from the submitted form
        user_id = session["user_id"] # Get the current user's ID from the session

        # Validate if task_id was provided
        if not task_id:
            return apology("Missing task ID to mark as done")

        try:
            # Update the status of the task to 'done' in the database
            # Ensure that the task belongs to the current user for security
            rows_affected = db.execute("UPDATE lists SET status = 'done' WHERE id = ? AND user_id = ?", task_id, user_id)

            if rows_affected > 0:
                # If the update was successful, flash a message and redirect
                flash("Task marked as done!", "success")
                return redirect("/") # Redirect back to the active tasks list
            else:
                # If no rows were affected, it means the task was not found or didn't belong to the user
                return apology("Could not mark task as done, or task not found/not authorized.", 400)

        except Exception as e:
            # Catch any database errors
            print(f"Database update error: {e}")
            return apology(f"An error occurred while marking task as done: {e}")
    else:
        # This route is intended for POST requests (to perform an action).
        # If a GET request somehow reaches here, redirect to the homepage.
        return redirect("/")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirm"):
            return apology("must confirm password", 400)

        # Ensure conformation was submitted
        elif request.form.get("password") != request.form.get("confirm"):
            return apology("password do not match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 0:
            return apology("username already exists", 400)

        db.execute("INSERT INTO users (username, hash) VALUES (?,?)",
                    request.form.get("username"), generate_password_hash(request.form.get("password")))

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        session["user_id"] = rows[0]["id"]
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")



