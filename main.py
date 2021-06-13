import streamlit as st
import base64
import hashlib
import sqlite3
import re
import stegano
from stegano import lsb
import random
import os

import numpy as np
import streamlit.components.v1 as stc
import pandas as pd
from PIL import Image
from tempfile import NamedTemporaryFile

regex = '^(\w | \. | \_ | \- )+[@](\w|\_|\-|\.)+[.]\w{2,3}$'

try:
    import os
    import io
    import requests
    import sys
    import streamlit as st
    import pandas as pd
    from io import BytesIO, StringIO
    from PIL import Image

    print("All Modules Loaded")
except Exception as e:
    print("Some Modules are Missing : {}".format(e))

STYLE = """
<style>
img{
    max-width: 100%
}
</style>
"""

main_bg = "pic2.jpg"
main_bg_ext = "jpg"

side_bg = "pic2.jpg"
side_bg_ext = "jpg"

st.markdown(
    f"""
    <style>
    .report view-container {{
        background: url(data:image/{main_bg_ext};base64,{base64.b64encode(open(main_bg, "rb").read()).decode()})
    }}
   .sidebar .sidebar-content {{
        background: url(data:image/{side_bg_ext};base64,{base64.b64encode(open(side_bg, "rb").read()).decode()})
    }}
    </style>
    """,
    unsafe_allow_html=True
)

# This is another section

HTML_BANNER = """
    <div style="background-color:#464e5f;padding:10px;border-radius:10px">
    <h1 style="color:white;text-align:center;">SteganoFix</h1>
    <p style="color:white;text-align:center;">Built with Streamlit</p>
    </div>
    """


# Security
# passlib,hashlib,bcrypt,scrypt


def make_hashes(password):
    return hashlib.sha256(str.encode(password)).hexdigest()


def check_hashes(password, hashed_text):
    if make_hashes(password) == hashed_text:
        return hashed_text
    return False


# DB Management


conn = sqlite3.connect('data.db', check_same_thread=False)
c = conn.cursor()


# DB  Functions
def create_users_table():
    c.execute('CREATE TABLE IF NOT EXISTS users_table(email NVARCHAR,username VARCHAR,password VARCHAR, '
              'account_creation_date DATE)')


def add_userdata(email, username, password, account_creation_date):
    c.execute('INSERT INTO users_table(email,username,password,account_creation_date) VALUES (?,?,?,?)',
              (email, username, password, account_creation_date))
    conn.commit()


def login_user(email, username, password):
    c.execute('SELECT * FROM users_table WHERE email =? AND username =? AND password = ?', (email, username, password))
    data = c.fetchall()
    return data


def view_all_users():
    c.execute('SELECT * FROM users_table')
    data = c.fetchall()
    return data


def view_all_user_email():
    c.execute('SELECT DISTINCT email FROM users_table')
    data = c.fetchall()
    return data


def get_user_by_email(email):
    c.execute('SELECT * FROM users_table WHERE email="{}"'.format(email))
    data = c.fetchall()
    return data


def delete_data(email):
    c.execute('DELETE FROM users_table WHERE email="{}"'.format(email))
    conn.commit()


def view_user_record():
    c.execute('SELECT DISTINCT email, username, account_creation_date FROM users_table')
    data = c.fetchall()
    return data


def update_user_data():
    with st.beta_expander("Current Data"):
        result = view_all_users()
        clean_df = pd.DataFrame(result, columns=["Email", "Username", "password", "account_creation_date"])
        st.dataframe(clean_df)

    list_of_users = [i[0] for i in view_all_user_email()]
    # list_of_tasks = [i[0] for i in view_all_task_names()]
    selected_record = st.selectbox("Email", list_of_users)
    email_result = get_user_by_email(selected_record)
    with st.beta_expander("View Updated Data"):
        # result = view_all_data()
        result = view_all_users()
    # st.write(result)
    clean_df = pd.DataFrame(result, columns=["Email", "Username", "Password", "Account Creation Date"])
    st.dataframe(clean_df)


def delete_user_data():
    st.subheader("Delete")
    with st.beta_expander("View Data"):
        result = view_all_users()
        # st.write(result)
        clean_df = pd.DataFrame(result, columns=["Email", "Username", "password", "Date"])
        st.dataframe(clean_df)
    unique_list = [i[0] for i in view_all_user_email()]
    delete_by_email = st.selectbox("Select Email", unique_list)
    if st.button("Delete"):
        delete_data(delete_by_email)
        st.warning("Deleted: '{}'".format(delete_by_email))
    with st.beta_expander("Updated Data"):
        result = view_all_users()
        # st.write(result)
        clean_df = pd.DataFrame(result, columns=["Email", "Username", "Password", "Account Creation Date"])
        st.dataframe(clean_df)


def check(email):
    if re.search(regex, email):
        st.info("Valid Email")
    else:
        st.warning("Invalid Email")


def main():
    stc.html(HTML_BANNER)
    """Image Steganography"""

    st.title("Steganography Free App")

    menu = ["Home", "Login", "SignUp", "User's Guid", "Admin", "About"]
    choice = st.sidebar.selectbox("Menu", menu)
    image = Image.open('steg3.jpg')
    st.image(image, width=750)

    if choice == "Home":
        # st.subheader("Home")
        st.subheader("Steganography:")
        st.write("Steganography is the art of concealing information. In computer science, "
                 "it refers to hiding data within a message or file. It serves a similar "
                 "purpose to cryptography, but instead of encrypting data, steganography "
                 "simply hides it from the user.Invisible ink is an example of steganography "
                 "that is unrelated to computers. A person can write a message with clear or "
                 "'invisible' ink that can only be seen when another ink or liquid is applied "
                 "to the paper. Similarly, in digital steganography, the goal is to hide information "
                 "from users except those who are meant to see or hear it.")
        # st.subheader("Nothing Looks Suspicious")

        if st.checkbox("History"):
            st.subheader("History:")
            st.write("Steganography has been with us for ages, be it the spies in the Revolutionary War writing in "
                     "invisible ink or Da Vinci embedding a secret meaning in a painting. Steganography traces its "
                     "roots back to 500 BC. The first physical case of steganography is found in Histories by "
                     "Herodotus, where he talks about the Greek leader Histiaeus’ act.  Histiaeus was stuck in an "
                     "enemy camp and was in dire need of sending a message to his camp. He then resorted to shaving "
                     "a trusted slave’s head, tattooing a secret message on his scalp, letting his hair grow, and then "
                     "sending him off to be shaved again by the message’s recipient On the other end of the timeline, "
                     "steganography is also being used recently. It is expected to be in use in the forthcoming years. "
                     "For example, it was used very recently to drop malware into user’s computers, by sending them "
                     "innocent-looking messages but hiding the malware within, using steganography techniques.")
            image = Image.open('steg6.jpg')
            st.image(image, width=750)

        if st.checkbox("Further Details"):
            st.subheader("Use cases or applications of steganography")
            st.write("Although the prime objective is to share messages or information discreetly, "
                     "it has found varied fields of applications such as ")
            st.write("Hackers using steganography techniques for malware transmission")
            st.write("Intelligence agencies use them for communication.")
            st.write("Printers also use micro-dots as a steganography tool to embed timestamps and date")
            st.write("information within the document.Also, the same technique is used in bank-note printing,to")
            st.write("prevent colour copiers from reproducing images of currency as fake-notes. ")
            image = Image.open('steg4.jpg')
            st.image(image, width=750)

        if st.checkbox("Detecting Steganography"):
            st.subheader("Detecting Steganography")
            st.write("Although it might be possible to detect physical steganography, it is extremely difficult "
                     "to detect digital steganography. Even if some activity is suspected, say some messages are "
                     "hidden within images, trying to monitor all images that are exchanged, and comparing them to "
                     "source images would result in lots of false positives and false negatives. That said, experts "
                     "still use a variety of techniques, including image histogram comparisons to detect hidden "
                     "messages, ‘conditional’ to them suspecting some covert message exchange")
            st.write(" ")
            st.write("Here is example in which it is very difficult to detect")
            image = Image.open('steg10.png')
            st.image(image, width=750)
            st.write("There is Two Images First one is 'Simple Image' & in 'Second Image' have secret message ")
            st.write("Both are looking same! that's why it is very difficult to detect it")
            st.write("Here is Properties file However if we look into the file properties, marked in red, their sizes "
                     "are very different.")
            image = Image.open('steg9.png')
            st.image(image, width=750)
            st.write("As we would imagine in the real-world, the sender and intended receiver would be in different "
                     "locations. Hence, this implementation is expected to work even without the original images.")
            st.write("It is not necessary the receiver have original image and the Image send by sender is Not "
                     "looking suspicious, that's why it is difficult to detect")
            st.info("Nothing Looks Suspicious here!")

        if st.checkbox("Reference"):
            st.write("[Research Article Steganography](https://scialert.net/fulltext/?doi=itj.2004.245.269)")
            st.write("[Another Article on Steganography](https://techterms.com/definition/steganography#:~:text"
                     "=Steganography%20is%20the%20art%20of,hides%20it%20from%20the%20user.)")
            st.write("[Further Details about Steganography]("
                     "https://www.mygreatlearning.com/blog/image-steganography-explained/)")
            st.write(
                "[Working of Steganography](https://www.geeksforgeeks.org/image-based-steganography-using-python/)")

    elif choice == "Login":
        st.subheader("Welcome User")

        email = st.sidebar.text_input("Email")
        # check(email)
        username = st.sidebar.text_input("User Name")
        password = st.sidebar.text_input("Password", type='password')

        if st.sidebar.checkbox("Login"):
            check(email)
            create_users_table()
            hashed_pswd = make_hashes(password)

            result = login_user(email, username, check_hashes(password, hashed_pswd))
            if result:

                st.success("Logged In as {}".format(username))
                st.balloons()
                st.subheader("Select the Options below that you want!")
                options = ["Select Option", "Encode", "Decode"]
                choice = st.selectbox("Options", options)

                if choice == "Select Option":
                    st.subheader("")
                elif choice == "Encode":
                    st.subheader("Encode:")
                    st.subheader("Encode Your Data")

                    uploaded_file = st.file_uploader("Upload Files", type=['png', 'jpeg', 'jpg'])
                    if uploaded_file is not None:
                        file_details = {"FileName": uploaded_file.name, "FileType": uploaded_file.type,
                                        "FileSize": uploaded_file.size}
                        st.write(file_details)
                        image = Image.open(uploaded_file, 'r')
                        image = st.image(uploaded_file, width=700)
                        # image = image.show()
                        data = st.text_area("Enter data to be encoded : ", "Hello")
                        if len(data) == 0:
                            raise ValueError('Data is empty')
                        elif st.button('Submit'):

                            secret = lsb.hide(uploaded_file, data)
                            st.success("Message Hide Successfully")
                            # image = Image.open(secret)
                            # st.image(image, width= 700)

                            rand = random.randrange(1, 100)
                            if rand:
                                imagename = "Image" + str(rand)
                                imagenameExtention = imagename + ".png"
                                secret.save(imagenameExtention)
                                st.success(imagenameExtention + " Image Create Successfully")
                                st.title('Encode Image')

                                def get_binary_file_downloader_html(bin_file, file_label='File'):
                                    with open(bin_file, 'rb') as f:
                                        data = f.read()
                                    bin_str = base64.b64encode(data).decode()
                                    href = f'<a href="data:application/octet-stream;base64,{bin_str}" download="{os.path.basename(bin_file)}">Download {file_label}</a>'
                                    return href

                                st.markdown(get_binary_file_downloader_html(imagenameExtention, 'Encoded Image'),
                                            unsafe_allow_html=True)

                elif choice == 'Decode':
                    st.subheader("Decode:")
                    st.subheader("Decode Your Image Here")
                    uploaded_file = st.file_uploader("Upload Files", type=['png', 'jpeg', 'jpg'])
                    if uploaded_file is not None:
                        image = Image.open(uploaded_file)
                        image = st.image(uploaded_file, width=600)
                        clear_message = lsb.reveal(uploaded_file)
                        st.write("Secret Message is : ")
                        st.info(clear_message)
                        st.success("Message Decode Successfully")
            else:
                st.warning("Sorry!, you can not login in, please check your user name or password")

    elif choice == "SignUp":
        st.subheader("Create New Account")
        new_email = st.text_input("Email")
        check(new_email)
        # check(new_email)
        new_user = st.text_input("Username")
        new_password = st.text_input("Password", type='password')
        new_account_creation_date = st.date_input("Enter Date")

        if st.button("Signup"):
            create_users_table()
            add_userdata(new_email, new_user, make_hashes(new_password), new_account_creation_date)
            st.success("You have successfully created a valid Account")
            st.balloons()
            st.info("Go to Login Menu to login")

    elif choice == "User's Guid":
        st.subheader("How To Use this Tool")
        options = ["IF You are New User", "IF Your  Account Already Exit"]
        choice = st.radio("Choose the Operation", options)
        if choice == "IF You are New User":
            st.subheader("Instruction To use this Tool")
            st.subheader("IF You are New User")
            st.write("If You are New User, Firstly Make an account by SignUp")
            image = Image.open('pic1.jpeg')
            st.image(image, width=750)
            st.write("Fill all the Fields")
            image = Image.open('picture2.PNG')
            st.image(image, width=750)
            st.write(" GoTo Login Menu to Use this Tool:")
            image = Image.open('picture3.PNG')
            st.image(image, width=750)
            st.write(" Login Your Account Successfully then you have more options 'Encode and Decode' ")
            image = Image.open('picture4.PNG')
            st.image(image, width=750)
            st.write("Select the option that you want ")
            image = Image.open('picture5.PNG')
            st.image(image, width=750)
            st.write("If you want to hide your message in Image then select 'Encode' ")
            image = Image.open('picture5.PNG')
            st.image(image, width=750)
            st.write("After that you have to upload an image in which you want to hide your Message")
            image = Image.open('picture6.PNG')
            st.image(image, width=750)
            st.write("Then Write a Secret Message ")
            image = Image.open('picture7.PNG')
            st.image(image, width=750)
            st.write("If your message Encode successfully, you will get Successfully message with new Image name")
            image = Image.open('picture8.PNG')
            st.image(image, width=750)
            st.write("If you select second option 'Decode'")
            image = Image.open('picture9.PNG')
            st.image(image, width=750)
            st.write("Upload the image that you want to decode")
            image = Image.open('picture10.PNG')
            st.image(image, width=750)
            st.write("You will get your Secret Message and Successful message")
            image = Image.open('picture11.PNG')
            st.image(image, width=750)
            if st.button("Got it"):
                st.balloons()

        elif choice == "IF Your  Account Already Exit":
            st.subheader("IF Your  Account Already Exit")
            st.write(" GoTo Login Menu to Use this Tool:")
            image = Image.open('picture3.PNG')
            st.image(image, width=750)
            st.write(" Login Your Account Successfully then you have more options 'Encode and Decode' ")
            image = Image.open('picture4.PNG')
            st.image(image, width=750)
            st.write("Select the option that you want ")
            image = Image.open('picture5.PNG')
            st.image(image, width=750)
            st.write("If you want to hide your message in Image then select 'Encode' ")
            image = Image.open('picture5.PNG')
            st.image(image, width=750)
            st.write("After that you have to upload an image in which you want to hide your Message")
            image = Image.open('picture6.PNG')
            st.image(image, width=750)
            st.write("Then Write a Secret Message ")
            image = Image.open('picture7.PNG')
            st.image(image, width=750)
            st.write("If your message Encode successfully, you will get Successfully message with New Image Name")
            image = Image.open('picture8.PNG')
            st.image(image, width=750)
            st.write("If you select second option 'Decode'")
            image = Image.open('picture9.PNG')
            st.image(image, width=750)
            st.write("Upload the image that you want to decode")
            image = Image.open('picture10.PNG')
            st.image(image, width=750)
            st.write("You will get your Secret Message and Successful message")
            image = Image.open('picture11.PNG')
            st.image(image, width=750)
            if st.button("Got it"):
                st.balloons()

    elif choice == "Admin":
        st.subheader("Welcome Admin")

        def authenticate(email, username, password):
            return email == "admin999@gmail.com" and username == "admin999" and password == "Admin@789"

        email = st.text_input("Email")
        check(email)
        username = st.text_input('Admin_Name')
        password = st.text_input("password", type='password')
        if st.checkbox("Login"):
            if authenticate(email, username, password):
                st.success('You are Successfully Login as Admin !')
                st.balloons()
                task = st.selectbox("Task", ["Select option", "Profiles"])
                if task == "Profiles":
                    st.subheader("Users Profiles")
                    # user_result = view_all_users()
                    user_result = view_user_record()
                    clean_db = pd.DataFrame(user_result,
                                            columns=["Email", "Username", "Account_Creation_Date"])
                    st.dataframe(clean_db)
                    delete_user_data()
            else:
                st.error('The username or password you have entered is invalid.')

    elif choice == "About":
        st.subheader("About me")
        st.info("I'm Currently Student")
        st.subheader("You Can Content me Via Email and Number")
        st.info("Contact Number: 03xx-xxxxxxx")
        st.info("This Is my Email id : 'abcxyz@gmail.com'")

        if st.button("About Project"):
            st.subheader("steganography")
            st.write("This Project Is build Up with streamlit")
            st.write("Stenography is basically a technique in which you can hide your data in any file. "
                     "This file may be a image, audio or video. and here 'data' mean anything that you"
                     "can hide it may be a simple message,text file,image,audio or video.This Project is "
                     "basically a Image Steganography. in Image Steganography you can hide your data or"
                     "message in Image.after successfully encode your message in a image you can decode "
                     "it.in this project also have a decode option.By decoding image you can see what is "
                     "secret message behind the image.")
            st.subheader("Functionality of Project:")
            st.text("1)  Home : There is some Basic Information About Topic")
            st.text("2)  Login : After Login You can see Options of 'Encode' & 'Decode'")
            st.text("3)  Sign up : Every user must be Sign up to use this application")
            st.text("4)  Admin : In admin Panel There is some extra privileges i.e He/She can see all user with ")
            st.text(".    needed Information of users and Admin can delete the record of any user")
            st.text("5)  About : In About you can contact us and little bit detail about project")


if __name__ == '__main__':
    main()
