MFA the Right Way: One Time Passwords with PyOTP
===

Presented at PyGotham 2018
---

MFA is an important strategy for modern application security. This repository proides an example of how to implement optional MFA in Django using the [PyOTP](https://github.com/pyotp/pyotp) library.

#### IMPORTANT: This Django project is for demonstration purposes only, and is NOT suitable for production use.

---

### How to Run

1. Install dependencies with [Poetry](https://poetry.eustace.io/)

  ```
  $ poetry install

  ```

2. Create a user to log in as
  ```
  $ python manage.py createsuperuser --username=[your_username] --email=[your_email]
  ```

3. Run the Django development server
  ```
  $ python manage.py runserver
  ```

4. That's it! Visit http://localhost:8000 and log in. Once in, you can enable MFA from the profile screen.
