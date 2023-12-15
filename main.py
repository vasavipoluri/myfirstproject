from typing import Dict, Any
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, status, Request,Form,Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse 
from fastapi.responses import JSONResponse,RedirectResponse,Response
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient 
from bson import ObjectId 
import random
import string 
from fastapi import BackgroundTasks
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel 
import random 
import secrets
app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB connection
myclient = MongoClient("mongodb://localhost:27017/")
mydb = myclient["myrealdatabase"]
users_col = mydb["user"]
students_col = mydb["student_details"]
# Update MongoDB collection schema
users_col.update_many({}, {"$set": {"course_registered": False}})

# Create a counter collection to keep track of the latest ID
counters_col = mydb["counters"] 

# Your existing JWT configuration
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Existing models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

def create_access_token(data: dict, request: Request):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Create a Response object with the access token as a cookie
    response = JSONResponse(content={"access_token": encoded_jwt, "token_type": "bearer"})
    response.set_cookie(key="access_token", value=encoded_jwt, httponly=True, secure=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60)

    # Add a redirection header to the response
    
    response.headers["location"] = str(request.url_for("home"))

    response.status_code = status.HTTP_303_SEE_OTHER

    return response 

# Existing function to get the current user from the token
def get_current_user(request: Request):
    print("Checking authentication...")
    authorization_cookie = request.cookies.get("access_token")

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        if not authorization_cookie:
            raise credentials_exception

        token = authorization_cookie
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        token_data = TokenData(username=username)
        return token_data

    except JWTError as e:
        print(f"JWTError during token decoding: {e}")
        raise credentials_exception

    except Exception as e:
        print(f"Unexpected error in get_current_user: {e}")
        raise credentials_exception


def get_next_sequence_value(sequence_name):
    sequence_doc = counters_col.find_one_and_update(
        {"_id": sequence_name},
        {"$inc": {"sequence_value": 1}},
        return_document=True,
        upsert=True,
    )
    return sequence_doc["sequence_value"]

# Get the next available ID from the counter
common_id = get_next_sequence_value("common_id")

# Existing function to verify the password format
def is_valid_password(password):
    errors = []

    if len(password) < 8:
        errors.append("Password is too short") 
    if not any(char.isupper() for char in password):
        errors.append("Password doesn't contain an uppercase letter")

    if not any(char.islower() for char in password):
        errors.append("Password doesn't contain a lowercase letter")

    if not any(char in string.punctuation for char in password):
        errors.append("Password doesn't contain a special character")

    if not any(char.isdigit() for char in password):
        errors.append("Password doesn't contain a digit")

    return errors  # List of error messages, empty if password is valid



@app.post("/login", response_model=Token)
async def verify_user(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        # Check if the user exists in the database
        existing_user = users_col.find_one({"username": username})

        if existing_user and password_context.verify(password, existing_user["password"]):
            if existing_user.get("course_registered", False):
                # If the user is already registered, redirect to the "already_registered" template
                response = RedirectResponse(url=request.url_for("already_registered"))
                return response
            else:
                # If the user is not registered, proceed with the regular login flow
                return create_access_token(data={"sub": username}, request=request)
        else:
            # Return an error message in the login form
            return templates.TemplateResponse("login.html", {"request": request, "message": "Invalid Email or Password"})

    except HTTPException as e:
        # Catch FastAPI HTTP exceptions and re-raise
        raise e

    except Exception as e:
        # Handle unexpected exceptions
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.get("/reset", response_class=HTMLResponse)
def reset_password_view(request: Request):
    return templates.TemplateResponse("reset.html", {"request": request})

@app.get("/")
def read_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/login")
def read_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/home", response_class=HTMLResponse)
def home(request: Request, current_user: TokenData = Depends(get_current_user)):
    try:
        print(f"Request to /home - User: {current_user.username}")
        # Your existing code for the dashboard goes here
        return templates.TemplateResponse("home.html", {"request": request, "user": current_user.username})
    except HTTPException as e:
        # Handle the validation error and return a custom response
        print(f"Error in /home: {e}")
        return templates.TemplateResponse("login.html", {"request": request, "message": "Unauthorized access. Please log in."})
    except Exception as e:
        # Print or log any unexpected errors
        print(f"Unexpected error in /home: {e}")
        return templates.TemplateResponse("login.html", {"request": request, "message": "Internal Server Error"})


@app.get("/signup", response_class = HTMLResponse)
def signup_form_route(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

# Email configuration
EMAIL_HOST = "your-smtp-host"
EMAIL_PORT = 587  # or the appropriate port for your SMTP server
EMAIL_USER = "vasavi1997.poluri@gmail.com"
EMAIL_PASSWORD = "bvza kzaz shpa csog"

def send_otp_email(email: str, otp: str):
    # Replace the following lines with your email sending logic (using SMTP or an email API)
    sender_email = "vasavi1997.poluri@gmail.com"  # Replace with your email
    receiver_email = email
    password = "bvza kzaz shpa csog"  # Replace with your email password

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Password Reset OTP"

    body = f"Your OTP for password reset: {otp}"
    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())

@app.post("/generate-otp")
async def generate_otp(request:Request, username: str = Form(...)):
    # Check if user exists in the database
    existing_user = users_col.find_one({"username": username})

    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Use the "username" as the email value
    email = existing_user["username"]
    # Generate a 6-digit OTP (for demonstration purposes)
    otp = str(random.randint(100000, 999999))

    # Save the OTP in the user document in the database
    users_col.update_one({"username": username}, {"$set": {"otp": otp}})

    # Send the OTP to the user's email
    send_otp_email(email ,otp)

    return templates.TemplateResponse("enter-otp.html",{"request":request, "message": "OTP generated and sent successfully"})


@app.post("/verify-and-update")
def verify_and_update(
    request: Request,
    username: str = Form(...),
    otp: str = Form(...),
    newpassword: str = Form(...),
):
    try:
        # Retrieve the OTP generated during the "generate-otp" step
        existing_user = users_col.find_one({"username": username})
        stored_otp = existing_user.get("otp", None)

        hashed_password = password_context.hash(newpassword)

        if stored_otp is not None and otp == stored_otp:
            # Update the password in the database
            users_col.update_one({"username": username}, {"$set": {"password": hashed_password}})

            # Optionally, you can remove the OTP field after updating the password
            users_col.update_one({"username": username}, {"$unset": {"otp": ""}})

            return templates.TemplateResponse("login.html", {"request": request, "message": "Password updated successfully"})
        else:
            raise HTTPException(status_code=400, detail="Invalid OTP")

    except Exception as e:
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/signup", response_class=HTMLResponse)
async def signup(request: Request, username: str = Form(...), password: str = Form(...), password_repeat: str = Form(...)):
    try:
        # Check if the user already exists
        existing_user = users_col.find_one({"username": username})
        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")

        if password != password_repeat:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        
        password_validation_errors = is_valid_password(password)

        if password_validation_errors:
            return templates.TemplateResponse("signup.html", {"request": request, "error_messages": password_validation_errors}) 
        
        hashed_password = password_context.hash(password)

        # Get the next available ID from the counter
        common_id = get_next_sequence_value("common_id") 
        
        users_col.insert_one({"_id": common_id, "username": username, "password": hashed_password})
        
        return templates.TemplateResponse("login.html", {"request": request, "message": "User Created Successfully!"})
    
    except HTTPException as e:
        print(f"Caught HTTPException: {e}")
        return templates.TemplateResponse("signup.html", {"request": request, "error_messages": [e.detail]})
    
    except Exception as e:
        print(f"Unexpected error: {e}")
        return templates.TemplateResponse("signup.html", {"request": request, "error_messages": ["Internal Server Error"]})

@app.post("/registration", response_class=HTMLResponse)
def register_student(
    request: Request,
    firstName: str = Form(...),
    lastName: str = Form(...),
    dob: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    collegename: str = Form(...),
    degree: str = Form(...),
    course: str = Form(...),
    current_user: TokenData = Depends(get_current_user)
):
    try:
        # Check if the user has already registered for the course
        existing_registration = students_col.find_one({"email": email, "course_registered": True})
        if existing_registration:
            # User is already registered, redirect to a page with a message
            return templates.TemplateResponse("already_registered.html", {"request": request, "user": current_user.username})

        # Check if the user has already registered for the course using the current username
        existing_user_registration = students_col.find_one({"email": current_user.username, "course_registered": True})
        if existing_user_registration:
            # User is already registered, redirect to a page with a message
            return templates.TemplateResponse("already_registered.html", {"request": request, "user": current_user.username})

        # Inserting the student data into the MongoDB collection
        student_data = {
            "_id": common_id,
            "firstname": firstName,
            "lastname": lastName,
            "dateofbirth": dob,
            "email": email,
            "phone": phone,
            "collegename": collegename,
            "degree": degree,
            "course": course,
            "course_registered": True,  # Set course registration status to True
        }
        result = students_col.insert_one(student_data)

        # Check if the insertion was successful
        if result.inserted_id:
            # Update the user document to indicate course registration
            users_col.update_one({"username": current_user.username}, {"$set": {"course_registered": True}})
            print(f"Update Result: {result}")
            # Retrieve the updated user data
            user_data = students_col.find()
            
            return templates.TemplateResponse("studentdetails.html", {"request": request, "user_data": user_data, "user": current_user.username})
        else:
            raise HTTPException(status_code=500, detail="Failed to insert data into MongoDB")

    except HTTPException as e:
        # Pass the exception details to the template
        return templates.TemplateResponse("studentdetails.html", {"request": request, "message": f"Error: {e.detail}"})

    except Exception as e:
        # Handle unexpected exceptions
        print(f"Error: {e}")
        # Pass the exception details to the template
        return templates.TemplateResponse("studentdetails.html", {"request": request, "message": "Internal Server Error"})

@app.get("/student/{common_id}", response_class=JSONResponse)
def get_student_details(common_id: int,current_user: TokenData = Depends(get_current_user)):
    try:
        # Find the student by ID in the MongoDB collection
        student = students_col.find_one({"_id": common_id})

        if student:
            # Return the student details as a JSON response
            return JSONResponse(content={"student": student,"user": current_user.username})
        else:
            # If the student ID is not found, return a 404 Not Found response
            raise HTTPException(status_code=404, detail="Student not found")

    except Exception as e:
        # Handle unexpected exceptions
        print(f"Error: {e}")
        # Return a 500 Internal Server Error response
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/registration", response_class=HTMLResponse)
def dashboard(request: Request, current_user: TokenData = Depends(get_current_user)):
    return templates.TemplateResponse("registration.html", {"request": request, "user": current_user.username})

@app.get("/studentdetails", response_class=HTMLResponse)
def dashboard(request: Request, current_user: TokenData = Depends(get_current_user)):
    user_data = students_col.find()
    return templates.TemplateResponse("studentdetails.html", {"request": request, "user": current_user.username, "user_data": user_data})


@app.get("/edit-student/{common_id}", response_class=HTMLResponse)
def edit_student_form(request: Request, common_id: int, current_user: TokenData = Depends(get_current_user)):
    # Retrieve the student details by ID
    student = students_col.find_one({"_id": common_id})

    # Check if the current user is the owner of the course registration
    if student["email"] != current_user.username:
        raise HTTPException(status_code=403, detail="Forbidden: You don't have permission to edit this course registration")

    # Render the edit form with existing student details
    return templates.TemplateResponse("edit_student.html", {"request": request, "user": current_user.username, "student": student})


from fastapi import HTTPException

@app.post("/edit-student/{common_id}")
async def edit_student(
    common_id: int,
    current_user: TokenData = Depends(get_current_user),
    firstname: str = Form(...),
    lastName: str = Form(...),
    dob: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    collegename: str = Form(...),
    degree: str = Form(...),
    course: str = Form(...),
):
    try:
        # Check if the current user is the owner of the course registration
        student = students_col.find_one({"_id": common_id})
        if student["email"] != current_user.username:
            raise HTTPException(status_code=403, detail="Forbidden: You don't have permission to edit this course registration")

        # Construct the updated_data dictionary
        updated_data = {
            "firstname": firstname,
            "lastName": lastName,
            "dob": dob,
            "email": email,
            "phone": phone,
            "collegename": collegename,
            "degree": degree,
            "course": course,
        }

        # Update the student details in the database
        students_col.update_one({"_id": common_id}, {"$set": updated_data})

        # Redirect to the student details page after editing
        return {"message": "Student details updated successfully"}
        
    except Exception as e:
        # Handle unexpected exceptions
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/delete-student/{common_id}")
def delete_student(common_id: int, current_user: TokenData = Depends(get_current_user)):
    # Check if the current user is the owner of the course registration
    student = students_col.find_one({"_id": common_id})
    if student["email"] != current_user.username:
        raise HTTPException(status_code=403, detail="Forbidden: You don't have permission to delete this course registration")

    # Delete the student record from the database
    students_col.delete_one({"_id": common_id})

    # Redirect to the student details page after deleting               
    

@app.get("/contactus", response_class = HTMLResponse)
def dashboard(request: Request,current_user: TokenData = Depends(get_current_user)):
    return templates.TemplateResponse("contactus.html", {"request": request,"user": current_user.username}) 


@app.get("/courses", response_class=HTMLResponse)
def dashboard(request: Request, current_user: TokenData = Depends(get_current_user)):
    return templates.TemplateResponse("courses.html", {"request": request, "user": current_user.username})

@app.get("/logout")
def user_logout(request: Request, current_user: TokenData = Depends(get_current_user)):
    return templates.TemplateResponse("login.html", {"request": request, "user": current_user.username, "message": "Logout Successful!"})