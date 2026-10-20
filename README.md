# UserHub

A Ruby web application for user registration, authentication, and account management, built with Sinatra and SQLite.

## Features

### User Authentication
- User registration with name, email, and password
- Secure password hashing using BCrypt
- Login and logout functionality
- Duplicate email prevention
- Session-based authentication
- Private dashboard for authenticated users
- CSRF token validation for POST requests

### Dashboard
- Personalized welcome message
- Total registered user count
- Display of the authenticated user's email address
- Responsive interface for desktop and mobile devices

## Tech Stack

- **Ruby** — Application programming language
- **Sinatra** — Web framework
- **SQLite** — Database
- **BCrypt** — Password hashing
- **ERB** — Server-rendered HTML templates
- **HTML and CSS** — User interface
- **Rackup / Puma** — Application server tooling

## Requirements

- Ruby
- Bundler
- Git

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/marykhodaparast/ruby-userhub.git
cd ruby-userhub
```

### 2. Install dependencies

```bash
bundle install
```

### 3. Configure the session secret

Set a secret key in your environment before starting the application:

```bash
export SESSION_SECRET="$(ruby -rsecurerandom -e 'puts SecureRandom.hex(64)')"
```

Keep this secret private. Do not commit it to the repository.

### 4. Start the application

```bash
bundle exec rackup config.ru -p 9292
```

### 5. Open the application

Visit:

- Registration: http://127.0.0.1:9292/register
- Login: http://127.0.0.1:9292/login
- Dashboard: http://127.0.0.1:9292/dashboard

The SQLite database is created locally when the application starts.

## Security

- Passwords are stored as BCrypt hashes rather than plaintext.
- SQL queries use parameterized statements.
- Dashboard access requires authentication.
- POST requests are validated using CSRF tokens.
- Session configuration uses HTTP-only cookies and `SameSite=Lax`.

This project is under development. Additional security hardening and production deployment configuration may be required before public deployment.

## Project Roadmap

- [x] User registration and authentication
- [x] Private user dashboard
- [x] Basic CSRF protection
- [ ] API endpoints for querying user data
- [ ] Natural-language questions and AI-generated answers based on database results
- [ ] AI-powered application controls (optional)

## Author

[Maryam Khodaparast](https://github.com/marykhodaparast)
