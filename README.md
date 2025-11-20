# flask-mysql-auth-system

It is built using the Flask framework in Python, utilizing MySQL for persistence, and implementing essential features like role-based authentication, user registration with full validation, and APIs for listing, searching, and filtering users.


1. Login API (/login)

Functionality: Allows existing users to sign in.
Fields: Email and Password.
Security: Passwords are verified against stored hashes using bcrypt.
Session Management: Upon successful login, the user_id and user_role are stored in the Flask session to manage authentication and authorization across the application.

2. Registration API (/register)

Functionality: Allows new users to create an account.
Fields: Name, Email, Password, Role (Admin/Staff), Phone, City, Country.
Validation: Includes server-side validation for:
All fields are required (DataRequired).
Email format validity and uniqueness check.
Role validation (ensures input is strictly 'Admin' or 'Staff').
Security: Passwords are hashed using bcrypt before storage.

3. List Users API (/users)

This is a protected route with advanced querying capabilities.
Authentication & Authorization:
Requires a logged-in session.
Access Restricted: Only users with the Admin role can access this list. Non-Admin users are redirected.
Querying: The endpoint dynamically handles two query parameters:
Search Users: Allows searching by Name or Email (using SQL LIKE for partial matches).
Filter Users: Allows filtering the list by the Country field.
Implementation: Dynamic SQL is constructed based on the presence of search and country parameters.

4. User Details API (/users/<user_id>)

Retrieves and displays the full registration details for a specific user ID.
Role-Based Access Control (RBAC):
Admin Role: Can view the details of any user ID.
Staff/Other Role: Can only view their own registration details (i.e., user_id in URL must match the user_id in the session).
Implementation: The route checks the user_id in the URL against the session's user_id and user_role before executing the database query.
