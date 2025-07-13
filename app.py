from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session
import openai
import os
from dotenv import load_dotenv
import logging
from datetime import datetime, timedelta
import json
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
import email
from email.mime.text import MIMEText
import pickle
import tempfile
import stripe

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///email_classifier.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize extensions
db = SQLAlchemy(app)
Session(app)
CORS(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/oauth2callback')

# Stripe configuration
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')
STRIPE_PRICE_ID = os.getenv('STRIPE_PRICE_ID')  # Your €20/month price ID

# Gmail API scopes
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
]

# Email categories
EMAIL_CATEGORIES = [
    "spam",
    "important",
    "work",
    "personal",
    "newsletter",
    "promotional",
    "social",
    "finance",
    "travel",
    "other"
]

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    google_id = db.Column(db.String(120), unique=True, nullable=False)
    access_token = db.Column(db.Text, nullable=True)
    refresh_token = db.Column(db.Text, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Subscription fields
    subscription_status = db.Column(db.String(20), default='trial')  # trial, active, past_due, canceled
    stripe_customer_id = db.Column(db.String(120), nullable=True)
    stripe_subscription_id = db.Column(db.String(120), nullable=True)
    trial_ends_at = db.Column(db.DateTime, nullable=True)
    subscription_ends_at = db.Column(db.DateTime, nullable=True)
    
    emails = db.relationship('Email', backref='user', lazy=True)
    
    @property
    def is_subscription_active(self):
        """Check if user has active subscription or is in trial"""
        if self.subscription_status == 'trial':
            return self.trial_ends_at and self.trial_ends_at > datetime.utcnow()
        return self.subscription_status == 'active'
    
    @property
    def days_left_in_trial(self):
        """Get days remaining in trial"""
        if self.subscription_status == 'trial' and self.trial_ends_at:
            days_left = (self.trial_ends_at - datetime.utcnow()).days
            return max(0, days_left)
        return 0

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gmail_id = db.Column(db.String(120), unique=True, nullable=False)
    subject = db.Column(db.String(500), nullable=True)
    sender = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.String(20), default='high')
    is_read = db.Column(db.Boolean, default=False)
    received_at = db.Column(db.DateTime, nullable=False)
    classified_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def classify_email(email_content, email_subject=""):
    """Classify email content using OpenAI API"""
    try:
        prompt = f"""
        Please classify the following email into one of these categories: {', '.join(EMAIL_CATEGORIES)}
        
        Email Subject: {email_subject}
        Email Content: {email_content}
        
        Please respond with only the category name from the list above.
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an email classification assistant. Respond with only the category name."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=50,
            temperature=0.1
        )
        
        classification = response.choices[0].message.content.strip().lower()
        
        if classification not in EMAIL_CATEGORIES:
            classification = "other"
            
        return classification
        
    except Exception as e:
        logger.error(f"Error classifying email: {str(e)}")
        return "error"

def get_gmail_service(user):
    """Get Gmail service for authenticated user"""
    try:
        if not user.access_token:
            return None
            
        credentials = Credentials(
            token=user.access_token,
            refresh_token=user.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=SCOPES
        )
        
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            user.access_token = credentials.token
            user.token_expiry = credentials.expiry
            db.session.commit()
        
        return build('gmail', 'v1', credentials=credentials)
        
    except Exception as e:
        logger.error(f"Error getting Gmail service: {str(e)}")
        return None

def get_or_create_label(service, user_id, label_name):
    labels = service.users().labels().list(userId=user_id).execute().get('labels', [])
    for label in labels:
        if label['name'].lower() == label_name.lower():
            return label['id']
    label_obj = {
        'name': label_name,
        'labelListVisibility': 'labelShow',
        'messageListVisibility': 'show'
    }
    label = service.users().labels().create(userId=user_id, body=label_obj).execute()
    return label['id']

def apply_label_to_email(service, user_id, message_id, label_id):
    service.users().messages().modify(
        userId=user_id,
        id=message_id,
        body={'addLabelIds': [label_id]}
    ).execute()

def fetch_and_classify_emails(user, max_emails=50):
    """Fetch emails from Gmail and classify them"""
    try:
        service = get_gmail_service(user)
        if not service:
            return False
            
        # Get recent emails
        results = service.users().messages().list(
            userId='me',
            maxResults=max_emails,
            q='is:unread'  # Only fetch unread emails
        ).execute()
        
        messages = results.get('messages', [])
        
        for message in messages:
            try:
                # Check if email already exists
                existing_email = Email.query.filter_by(
                    user_id=user.id, 
                    gmail_id=message['id']
                ).first()
                
                if existing_email:
                    continue
                
                # Get full message details
                msg = service.users().messages().get(
                    userId='me', 
                    id=message['id'],
                    format='full'
                ).execute()
                
                # Extract email data
                headers = msg['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), '')
                
                # Extract content
                content = ''
                if 'parts' in msg['payload']:
                    for part in msg['payload']['parts']:
                        if part['mimeType'] == 'text/plain':
                            content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                            break
                elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
                    content = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')
                
                if not content:
                    content = subject  # Use subject if no content
                
                # Classify email
                category = classify_email(content, subject)

                # Create/apply Gmail label
                label_id = get_or_create_label(service, 'me', category.capitalize())
                apply_label_to_email(service, 'me', message['id'], label_id)
                
                # Parse received date
                date_header = next((h['value'] for h in headers if h['name'] == 'Date'), '')
                try:
                    received_at = datetime.strptime(date_header, '%a, %d %b %Y %H:%M:%S %z').replace(tzinfo=None)
                except:
                    received_at = datetime.utcnow()
                
                # Save email to database
                email_record = Email(
                    user_id=user.id,
                    gmail_id=message['id'],
                    subject=subject,
                    sender=sender,
                    content=content,
                    category=category,
                    received_at=received_at
                )
                
                db.session.add(email_record)
                
            except Exception as e:
                logger.error(f"Error processing email {message['id']}: {str(e)}")
                continue
        
        db.session.commit()
        return True
        
    except Exception as e:
        logger.error(f"Error fetching emails: {str(e)}")
        return False

# Routes
@app.route('/')
def index():
    """Main page - redirect to dashboard if logged in, otherwise show landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/manual')
def manual_classifier():
    """Manual email classifier page"""
    return render_template('index.html', categories=EMAIL_CATEGORIES)

@app.route('/login')
def login():
    """Initiate Google OAuth login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI]
            }
        },
        scopes=SCOPES
    )
    
    flow.redirect_uri = GOOGLE_REDIRECT_URI
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth callback from Google"""
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI]
                }
            },
            scopes=SCOPES,
            state=session['state']
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI
        
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        
        # Get user info from Google
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        # Check if user exists
        user = User.query.filter_by(google_id=user_info['id']).first()
        
        if not user:
            # Create new user with 1-month trial
            user = User(
                email=user_info['email'],
                name=user_info['name'],
                google_id=user_info['id'],
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_expiry=credentials.expiry,
                subscription_status='trial',
                trial_ends_at=datetime.utcnow() + timedelta(days=30)
            )
            db.session.add(user)
        else:
            # Update existing user's tokens
            user.access_token = credentials.token
            user.refresh_token = credentials.refresh_token
            user.token_expiry = credentials.expiry
        
        db.session.commit()
        login_user(user)
        
        flash('Successfully logged in with Google!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"OAuth error: {str(e)}")
        logger.error(f"Request URL: {request.url}")
        logger.error(f"Request args: {dict(request.args)}")
        flash('Login failed. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # Check subscription status
    if not current_user.is_subscription_active:
        flash('Your trial has expired. Please upgrade to continue using the service.', 'warning')
        return redirect(url_for('pricing'))
    
    # Get user's emails
    emails = Email.query.filter_by(user_id=current_user.id).order_by(Email.received_at.desc()).limit(100).all()
    
    # Get category statistics
    category_stats = db.session.query(
        Email.category, 
        db.func.count(Email.id).label('count')
    ).filter_by(user_id=current_user.id).group_by(Email.category).all()
    
    return render_template('dashboard.html', 
                         emails=emails, 
                         category_stats=category_stats,
                         categories=EMAIL_CATEGORIES,
                         now=datetime.utcnow(),
                         timedelta=timedelta,
                         user=current_user)

@app.route('/api/fetch-emails', methods=['POST'])
@login_required
def fetch_emails():
    """API endpoint to fetch and classify new emails"""
    # Check subscription status
    if not current_user.is_subscription_active:
        return jsonify({"success": False, "error": "Subscription required. Please upgrade to continue."}), 403
    
    try:
        success = fetch_and_classify_emails(current_user)
        if success:
            return jsonify({"success": True, "message": "Emails fetched and classified successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to fetch emails"}), 500
    except Exception as e:
        logger.error(f"Error in fetch_emails: {str(e)}")
        return jsonify({"success": False, "error": "Internal server error"}), 500

@app.route('/api/classify', methods=['POST'])
def classify_email_api():
    """API endpoint for manual email classification"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        email_content = data.get('content', '')
        email_subject = data.get('subject', '')
        
        if not email_content:
            return jsonify({"error": "Email content is required"}), 400
            
        category = classify_email(email_content, email_subject)
        
        if category == "error":
            return jsonify({"error": "Failed to classify email"}), 500
            
        return jsonify({
            "category": category,
            "confidence": "high",
            "categories": EMAIL_CATEGORIES
        })
        
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/categories', methods=['GET'])
def get_categories():
    """Get available email categories"""
    return jsonify({"categories": EMAIL_CATEGORIES})

@app.route('/api/emails', methods=['GET'])
@login_required
def get_emails():
    """Get user's emails with filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        category = request.args.get('category', '')
        
        query = Email.query.filter_by(user_id=current_user.id)
        
        if category:
            query = query.filter_by(category=category)
        
        emails = query.order_by(Email.received_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            "emails": [{
                "id": email.id,
                "subject": email.subject,
                "sender": email.sender,
                "category": email.category,
                "is_read": email.is_read,
                "received_at": email.received_at.isoformat(),
                "content_preview": email.content[:200] + "..." if len(email.content) > 200 else email.content
            } for email in emails.items],
            "total": emails.total,
            "pages": emails.pages,
            "current_page": page
        })
        
    except Exception as e:
        logger.error(f"Error getting emails: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/emails/<int:email_id>/read', methods=['POST'])
@login_required
def mark_email_read(email_id):
    """Mark email as read"""
    try:
        email = Email.query.filter_by(id=email_id, user_id=current_user.id).first()
        if not email:
            return jsonify({"error": "Email not found"}), 404
        
        email.is_read = True
        db.session.commit()
        
        return jsonify({"success": True})
        
    except Exception as e:
        logger.error(f"Error marking email read: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/pricing')
def pricing():
    """Pricing page"""
    return render_template('pricing.html', 
                         stripe_publishable_key=STRIPE_PUBLISHABLE_KEY,
                         price_id=STRIPE_PRICE_ID)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    """Create Stripe checkout session"""
    try:
        # Create or get Stripe customer
        if not current_user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=current_user.email,
                name=current_user.name
            )
            current_user.stripe_customer_id = customer.id
            db.session.commit()
        
        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=current_user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': STRIPE_PRICE_ID,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=request.host_url + 'dashboard',
            cancel_url=request.host_url + 'pricing',
            metadata={
                'user_id': current_user.id
            }
        )
        
        return jsonify({'id': checkout_session.id})
        
    except Exception as e:
        logger.error(f"Error creating checkout session: {str(e)}")
        return jsonify({'error': 'Failed to create checkout session'}), 500

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhooks"""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session['metadata']['user_id']
        user = User.query.get(user_id)
        
        if user:
            user.subscription_status = 'active'
            user.stripe_subscription_id = session['subscription']
            db.session.commit()
    
    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        user = User.query.filter_by(stripe_subscription_id=subscription['id']).first()
        
        if user:
            user.subscription_status = subscription['status']
            if subscription['status'] == 'canceled':
                user.subscription_ends_at = datetime.fromtimestamp(subscription['current_period_end'])
            db.session.commit()
    
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        user = User.query.filter_by(stripe_subscription_id=subscription['id']).first()
        
        if user:
            user.subscription_status = 'canceled'
            user.subscription_ends_at = datetime.fromtimestamp(subscription['current_period_end'])
            db.session.commit()
    
    return jsonify({'status': 'success'})

@app.route('/cancel-subscription', methods=['POST'])
@login_required
def cancel_subscription():
    """Cancel user subscription"""
    try:
        if current_user.stripe_subscription_id:
            stripe.Subscription.modify(
                current_user.stripe_subscription_id,
                cancel_at_period_end=True
            )
            current_user.subscription_status = 'canceled'
            db.session.commit()
            flash('Your subscription will be canceled at the end of the current period.', 'info')
        else:
            flash('No active subscription found.', 'error')
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Error canceling subscription: {str(e)}")
        flash('Error canceling subscription. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "email-classifier"})

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=3000)
