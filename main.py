from flask import Flask, render_template, redirect, url_for, flash,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,Form,login_form,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
Base = declarative_base()
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
#tells flask which table is which allocation
app.config['SQLALCHEMY_BINDS'] = {'user':'sqlite:///user.db','comment':'sqlite:///comment.db'}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
gravatar = Gravatar(app,
                    size=200,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
login_manager=LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES
#Parent
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #making the author column the linkage
    # Create Foreign Key, "users.id" the users refers to the tablename of User
    #The foriegn key refers to the table name of User
    author_id = db.Column(db.Integer, db.ForeignKey('users_information.id'))
    # Create reference to the User object, the "parent" refers to the parent property in the User class.
    #this allows you to tap into a the User database eg: author.name,the author property is now a User objec
    author = relationship("User", back_populates="posts")
    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")



##User table
#Child
class User(UserMixin, db.Model):
    __bind_key__ = 'user'
    __tablename__ = 'users_information'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # This will act like a List of BlogPost objects attached to each User.
    comments = relationship("Comment",back_populates = "comment_author")
    posts = relationship("BlogPost", back_populates="author")


class Comment(UserMixin, db.Model):
    __bind_key__ = 'comment'
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text =  db.Column(db.Text, nullable=False)
    #link to User table
    author_id = db.Column(db.Integer, db.ForeignKey('users_information.id'))
    comment_author = relationship("User", back_populates="comments")
    #link to blogpost
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()
posts = BlogPost.query.all()
@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))


def admin(func):
    @wraps(func)
    def wrapper(*args,**kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.name != "admin":
            return abort(403, description="Error 403")
        #have to return the function if not the functions wont work if its valid
        return func(*args,**kwargs)

    return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated)


@app.route('/register',methods=["POST","GET"])
def register():
    form = Form()
    if form.validate_on_submit():
        email = form.Email.data
        password = form.Password.data
        name = form.Name.data
        if User.query.filter_by(email=email).first():
          flash("You have already signed up with that email,log in instead!")
          return redirect(url_for('login'))
        # adding to new database
        hashed_salted_password = generate_password_hash(  # creating a hashed password
            password=password,
            salt_length=8,
            method='sha256'
        )
        new_user = User(
           email=email,
           name=name,
           password=hashed_salted_password,)

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)#the object is the single row of the database table
        return render_template("index.html", all_posts=posts,logged_in = True)

    return render_template("register.html",form = form)


@app.route('/login',methods=["POST","GET"])
def login():
    form = login_form()
    if form.validate_on_submit():
        email = form.Email.data
        password = form.Password.data
        check_email = User.query.filter_by(email = email).first()
        if not check_email:
            flash("That email does not exist,please try again. ")
            return redirect(url_for('login', form=form))
        elif not check_password_hash(check_email.password, password):  # checkagainst password and password hash
            flash('Password incorrect,please try again')
            return redirect(url_for('login', form=form))
        else:
            login_user(check_email)
            return render_template("index.html",logged_in=True)

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=["POST","GET"])
def show_post(post_id):
    form = CommentForm()
    all_comments = db.session.query(Comment).all()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to commen.")
            return redirect(url_for("login"))
        requested_post = BlogPost.query.get(post_id)
        data = form.body.data
        new_comment = Comment(
             text = data,
            author_id = current_user.id,
            post_id = post_id
         )
        db.session.add(new_comment)
        db.session.commit()
        return render_template("post.html", post=requested_post, form=form,comment = all_comments)
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post,form = form,comment = all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=["POST","GET"])
@admin
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
