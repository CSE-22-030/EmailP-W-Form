from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QMessageBox,
    QVBoxLayout, QHBoxLayout, QCheckBox
)
import sys
import re
import mysql.connector
import hashlib


class LoginForm(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PyQt5 Login & Signup System")
        self.setGeometry(100, 100, 400, 300)

        # Labels
        self.email_label = QLabel("Email:")
        self.password_label = QLabel("Password:")

        # Input fields
        self.email_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        # Show/Hide password
        self.show_password = QCheckBox("Show Password")
        self.show_password.toggled.connect(self.toggle_password_visibility)

        # Buttons
        self.login_button = QPushButton("Login")
        self.signup_button = QPushButton("Sign Up")
        self.reset_button = QPushButton("Reset")

        # Connect button actions
        self.login_button.clicked.connect(self.login_user)
        self.signup_button.clicked.connect(self.register_user)
        self.reset_button.clicked.connect(self.reset_form)

        # Layout setup
        layout = QVBoxLayout()
        layout.addWidget(self.email_label)
        layout.addWidget(self.email_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.show_password)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.signup_button)
        button_layout.addWidget(self.reset_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    # ---------------- VALIDATION ----------------

    def is_valid_email(self, email):
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email)

    def is_strong_password(self, password):
        pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        return re.match(pattern, password)

    # ---------------- DATABASE CONNECTION ----------------

    def connect_db(self):
        try:
            connection = mysql.connector.connect(
                host="localhost",
                user="root",          # 👉 change if you use another MySQL username
                password="root",      # 👉 change to your MySQL password
                database="user_db"
            )
            return connection
        except mysql.connector.Error as err:
            QMessageBox.critical(self, "Database Error", f"Error connecting to database:\n{err}")
            return None

    # ---------------- PASSWORD HASH ----------------

    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    # ---------------- BUTTON FUNCTIONS ----------------

    def toggle_password_visibility(self):
        if self.show_password.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)

    def register_user(self):
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()

        # Validate input
        if not email or not password:
            QMessageBox.warning(self, "Input Error", "Please fill in both fields!")
            return
        if not self.is_valid_email(email):
            QMessageBox.warning(self, "Invalid Email", "Please enter a valid email address.")
            return
        if not self.is_strong_password(password):
            QMessageBox.warning(self, "Weak Password",
                "Password must include at least 8 chars, one uppercase, one lowercase, one number, one special symbol.")
            return

        conn = self.connect_db()
        if conn is None:
            return

        cursor = conn.cursor()

        hashed_pw = self.hash_password(password)

        try:
            cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_pw))
            conn.commit()
            QMessageBox.information(self, "Success", "User registered successfully!")
        except mysql.connector.IntegrityError:
            QMessageBox.warning(self, "Duplicate", "This email is already registered.")
        finally:
            cursor.close()
            conn.close()

    def login_user(self):
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()

        if not email or not password:
            QMessageBox.warning(self, "Input Error", "Please enter both email and password!")
            return

        conn = self.connect_db()
        if conn is None:
            return

        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()

        if result is None:
            QMessageBox.warning(self, "Login Failed", "No account found with this email.")
        else:
            stored_hash = result[0]
            entered_hash = self.hash_password(password)
            if entered_hash == stored_hash:
                QMessageBox.information(self, "Login Successful", f"Welcome back, {email}!")
            else:
                QMessageBox.warning(self, "Login Failed", "Incorrect password.")

        cursor.close()
        conn.close()

    def reset_form(self):
        self.email_input.clear()
        self.password_input.clear()
        self.show_password.setChecked(False)
        QMessageBox.information(self, "Reset", "Form has been cleared!")

# ---------------- MAIN APP ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginForm()
    window.show()
    sys.exit(app.exec_())
