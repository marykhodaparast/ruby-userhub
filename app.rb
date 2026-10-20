
require "sinatra"
require "sqlite3"
require "bcrypt"
require "securerandom"
require "rack/utils"
require "json"

set :bind, "127.0.0.1"
set :port, 4567

set :session_secret, ENV.fetch("SESSION_SECRET") {
  SecureRandom.hex(64)
}

enable :sessions
set :sessions, httponly: true, same_site: :lax

DB_PATH = File.expand_path("userhub.sqlite3", __dir__)

def database
  db = SQLite3::Database.new(DB_PATH)
  db.results_as_hash = true
  db
end

# Create the database table when the application starts.
db = database
db.execute <<~SQL
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
SQL
db.close

helpers do
  def require_api_login!
  unless current_user
    content_type :json
    halt 401, { error: "Authentication required" }.to_json
  end
end
  def csrf_token
     session[:csrf_token] ||= SecureRandom.hex(32)
  end
  def h(value)
    Rack::Utils.escape_html(value.to_s)
  end

  def current_user
    return nil unless session[:user_id]

    db = database
    user = db.get_first_row(
      "SELECT id, name, email, created_at FROM users WHERE id = ?",
      session[:user_id]
    )
    db.close
    user
  end

  def require_login!
    return if current_user

    session[:error] = "Please log in to continue."
    redirect "/login"
  end

  def set_flash(type, message)
    session[type] = message
  end
end

before do
  if request.post?
    expected_token = session[:csrf_token]
    submitted_token = params[:csrf_token].to_s

    unless expected_token &&
           Rack::Utils.secure_compare(
             expected_token,
             submitted_token
           )
      halt 403, "Invalid or missing CSRF token. Please refresh the page and try again."
    end
  end

  @current_user = current_user
  @error = session.delete(:error)
  @success = session.delete(:success)
end

get "/" do
  redirect @current_user ? "/dashboard" : "/register"
end

get "/register" do
  redirect "/dashboard" if @current_user
  erb :register
end

post "/register" do
  name = params[:name].to_s.strip
  email = params[:email].to_s.strip.downcase
  password = params[:password].to_s

  if name.empty? || email.empty? || password.empty?
    @error = "All fields are required."
    return erb :register
  end

  unless email.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
    @error = "Please enter a valid email address."
    return erb :register
  end

  if password.length < 8
    @error = "Password must contain at least 8 characters."
    return erb :register
  end

  password_hash = BCrypt::Password.create(password)

  begin
    db = database
    db.execute(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, password_hash.to_s]
    )
    user_id = db.last_insert_row_id
    db.close

    session.clear
    session[:user_id] = user_id
    redirect "/dashboard"
  rescue SQLite3::ConstraintException
    db&.close
    @error = "An account with this email already exists."
    erb :register
  end
end

get "/login" do
  redirect "/dashboard" if @current_user
  erb :login
end

post "/login" do
  email = params[:email].to_s.strip.downcase
  password = params[:password].to_s

  db = database
  user = db.get_first_row(
    "SELECT id, name, email, password_hash FROM users WHERE email = ?",
    email
  )
  db.close

  if user && BCrypt::Password.new(user["password_hash"]) == password
    session.clear
    session[:user_id] = user["id"]
    redirect "/dashboard"
  else
    @error = "Invalid email or password."
    erb :login
  end
end

get "/dashboard" do
  require_login!
  @current_user = current_user

  db = database
  @user_count = db.get_first_value("SELECT COUNT(*) FROM users")
  db.close

  erb :dashboard
end

post "/logout" do
  session.clear
  redirect "/login"
end


# API: Get aggregate user statistics.
get "/api/users/stats" do
  require_api_login!
  content_type :json

  db = database

  begin
    total_users = db.get_first_value(
      "SELECT COUNT(*) FROM users"
    )

    gmail_users = db.get_first_value(
      "SELECT COUNT(*) FROM users WHERE LOWER(email) LIKE ?",
      "%@gmail.com"
    )

    {
      total_users: total_users,
      gmail_users: gmail_users
    }.to_json
  ensure
    db.close
  end
end

# API: Get the most recently registered users.
get "/api/users/recent" do
  require_api_login!
  content_type :json

  limit = params.fetch("limit", "5").to_i
  limit = [[limit, 1].max, 20].min

  db = database

  begin
    users = db.execute(
      "SELECT id, name, email, created_at
       FROM users
       ORDER BY created_at DESC, id DESC
       LIMIT ?",
      limit
    )

    {
      count: users.length,
      users: users.map do |user|
        {
          id: user["id"],
          name: user["name"],
          email: user["email"],
          created_at: user["created_at"]
        }
      end
    }.to_json
  ensure
    db.close
  end
end

# API: Search users by email domain.
get "/api/users/by-domain" do
  require_api_login!
  content_type :json

  domain = params["domain"].to_s.downcase.strip

  unless domain.match?(/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}\z/)
    halt 400, { error: "Please provide a valid email domain." }.to_json
  end

  db = database

  begin
    users = db.execute(
      "SELECT id, name, email, created_at
       FROM users
       WHERE LOWER(email) LIKE ?
       ORDER BY id DESC",
      "%@#{domain}"
    )

    {
      domain: domain,
      count: users.length,
      users: users.map do |user|
        {
          id: user["id"],
          name: user["name"],
          email: user["email"],
          created_at: user["created_at"]
        }
      end
    }.to_json
  ensure
    db.close
  end
end

not_found do
  "Page not found"
end
