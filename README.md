# flask-includes-captcha
A simple, limited (basic) wrap of the popular Captcha library for Flask projects.


The extension creates Captchas and corresponding tokens that can
be used for verification.


## Installation

Install this extension with pip:

```shell
$ pip install flask-includes-captcha
```
---
## Usage

Set up your app and  configure a secure Captcha Key:

```python
from flask import Flask

app = Flask(__name__)
app.config['CAPTCHA_KEY'] = "use a secure key" #change this
``` 

Import the Captcha class from this extension and initialize it with your app:

```python
from flask_includes_captcha import FlaskCaptcha

flask_captcha = FlaskCaptcha(app)
```

Create a form that includes a string field for the text that should be compared and a 
hidden field for the web token. Implement a function that validates if the
text matched with the Captcha:  

```python
from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField, SubmitField, ValidationError

class ProtectedForm(FlaskForm):
    captcha_text = StringField("Characters")
    captcha_token = HiddenField()
    submit = SubmitField("Submit")
    
    def validate_captcha_text(self, field):
        if not flask_captcha.verify(self.captcha_text.data, self.captcha_token.data):
            raise ValidationError("Wrong Captcha")
```

Send the Captcha image and the token with the form:

```python
from flask import render_template


@app.route('/captcha', methods=["GET", "POST"])
def captcha():
    form = ProtectedForm()

    if form.validate_on_submit():
        pass  # Start processing the form from here

    captcha = flask_captcha.create()
    form.captcha_token.data = captcha["token"]

    return render_template("form.html", captcha=captcha["image"], form=form)
```
The Captcha must be rendered in the template (./templates/form.html):

```html
<img src="data:image/png;base64,{{ captcha }}" alt="CAPTCHA">

<form action="" method="post">
    {{ form.hidden_tag() }}
    {{ form.captcha_text.label }}
    {{ form.captcha_text() }}
    {{ form.captcha_token }}
    {{ form.submit }}
</form>
```

## Dependencies 

- captcha
- flask
- flask-wtf
- joserfc
