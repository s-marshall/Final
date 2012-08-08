require 'sinatra'
require 'haml'
require 'data_mapper'
require 'dm-postgres-adapter'
require 'pg'
require 'thin'
require './secure'
require 'dalli'

enable :sessions
use Rack::CommonLogger
enable :logging

DataMapper::setup(:default, ENV['DATABASE_URL'] || 'postgres://localhost/password.db')

class Password
  include DataMapper::Resource

  property :id, Serial
  property :username, String
  property :password, Text
end

DataMapper::setup(:default, ENV['DATABASE_URL'] || 'postgres://localhost/wiki.db')
class Post
  include DataMapper::Resource

  property :id, Serial
  property :page_url, String
  property :content, Text
  property :created, DateTime, :default => Time.now
  property :permalink, String

  before :valid?, :set_permalink

  private
    def set_permalink
      self.permalink = id
    end
end

DataMapper.finalize
Password.auto_upgrade!
Post.auto_upgrade!

class PostBuffer
  attr_accessor :page_url, :content

  def initialize(page_url, content)
    @page_url = page_url
    @content = content
  end
end

$CACHE = Dalli::Client.new('localhost:11211')
$CACHE.flush_all

# Authorization

before '/signed_on/*' do
  redirect '/login' if session[:valid_password] != true
end

# Initialize wiki database
def initialize_wiki
  post = Post.first_or_create(:page_url => %Q{/})
  post.update(:content => %Q{<strong>Welcome to Final Wiki World</strong>})
end
initialize_wiki
post = Post.first(:page_url => '/')
edited_post = PostBuffer.new(post.page_url, post.content)

# Signup

def validate_username(username)
  username =~ /^[a-zA-Z0-9_-]{3,20}$/
end

def validate_password(password)
  password =~ /^.{3,20}$/
end

def validate_email(email)
  email =~ /^[\S]+@[\S]+\.[\S]+$/
end

def name_in_database?(name)
  entries = Password.all
  entries.each do |e|
    return true if e.username == make_secure_value(name)
  end
  return nil
end

def name_and_password_in_database?(name, password)
  secure_name = make_secure_value(name)
  pw = Password.all(:username => secure_name)
  if pw[0]
    pw[0].password =~ /^([^,]*),(.*)/
    if (get_value_from_hash(pw[0].username) == name) && check_for_validity(name, password, pw[0].password)
      return true
    end
  else
    return nil
  end
end

def write_form(username_error='', password_error='', verify_error='', email_error='')
  @invalid_username = username_error
  @invalid_password = password_error
  @invalid_verify = verify_error
  @invalid_email = email_error

  haml :signup, :locals =>
    {	:username => params[:username],
     	:password => params[:password],
    	:verify => params[:verify],
    	:email => params[:email]
    }
end

get '/signup' do
  haml :signup
end

post '/signup' do
  @valid_input = true
  session[:valid_password] = false

  if validate_username(params[:username]) == nil
    @invalid_username = %Q{This is not a valid username.}
    @valid_input = false
  elsif name_in_database?(params[:username])
    @invalid_username = %Q{This user already exists.}
    @valid_input = false
  else
    @invalid_username = ''
  end

  if validate_password(params[:password]) == nil
    @invalid_password = %Q{This is not a valid password.}
    @valid_input = false
  else
    @invalid_password = ''
  end

  if params[:password] != params[:verify]
    @invalid_verify = %Q{The passwords do not match.}
    @valid_input = false
  else
    @invalid_verify = ''
  end

  if (params[:email] != '') && (validate_email(params[:email]) == nil)
    @invalid_email = %Q{This is not a valid email address.}
    @valid_input = false
  else
    @invalid_email = ''
  end

  if @valid_input == true
    password_hash = make_password_hash(params[:username], params[:password], make_salt)
    session[:username] = make_secure_value params[:username]
    entry = Password.create(:username => session[:username], :password => password_hash)
    session[:valid_password] = true
    redirect '/'
  else
    write_form(@invalid_username, @invalid_password, @invalid_verify, @invalid_email)
  end
end

# Login

get '/login' do
  haml :login
end

post '/login' do
  @username = params[:username]
  @password = params[:password]
  session[:valid_password] = false
  if name_and_password_in_database?(@username, @password)
    session[:username] = make_secure_value @username
    @invalid_login = ''
    session[:valid_password] = true
    redirect '/'
  else
    @invalid_login = 'Invalid login'
  end
  haml :login
end

get '/logout' do
  session[:valid_password] = nil
  haml :logout, :locals => {:content => edited_post.content}
end

# Wiki
def render_post(action = 'edit', content = '')
  if session[:valid_password]
    haml action.to_sym, :locals => {:content => "#{content}"}
  else
    haml :logout, :locals => {:content => "#{content}"}
  end
end

get '/signed_on/edit/:page' do
  edited_post.page_url = params[:page]
  post = Post.first_or_create(:page_url => params[:page])
  if post.content != nil
    edited_post.content = post.content
  else
    edited_post.content = ''
    post.update(:content => '')
  end
  render_post('edit', edited_post.content)
end

get '/:page' do
  post = Post.first_or_create(:page_url => params[:page])
  if post.content != nil
    edited_post.page_url = post.page_url
    edited_post.content = post.content
    render_post('view', edited_post.content)
  else
    redirect "/signed_on/edit/#{params[:page]}"
  end
end

get '/' do
  post = Post.first_or_create(:page_url => '/')
  edited_post.page_url = post.page_url
  edited_post.content = post.content
  render_post('view', edited_post.content)
end

get '/signed_on/edit/' do
  if edited_post.page_url != '/'
    redirect "/signed_on/edit/#{edited_post.page_url}"
  end

  post = Post.first(:page_url => edited_post.page_url)
  if post.content.length > 0
    edited_post.content = post.content
  end
  render_post('edit', edited_post.content)
end

post '/signed_on/edit/:page' do
  edited_post.page_url = params[:page]
  edited_post.content = params[:content]
  post = Post.first_or_create(:page_url => params[:page])
  post.update(:content => params[:content])
  redirect "/#{params[:page]}"
end

post '/signed_on/edit/' do
  edited_post.content = params[:content]
  post = Post.first_or_create(:page_url => edited_post.page_url)
  post.update(:content => edited_post.content)
  redirect "#{edited_post.page_url}"
end
