import __init__  # type: ignore
import asyncio

from core.utils import send_email_async

# import smtplib
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart


# def send_email(subject, message, from_addr, to_addr, password):
#     # Create message
#     msg = MIMEMultipart()
#     msg["From"] = from_addr
#     msg["To"] = to_addr
#     msg["Subject"] = subject

#     # Attach the message to the MIMEMultipart object
#     msg.attach(MIMEText(message, "plain"))

#     try:
#         # Set up the SMTP server
#         server = smtplib.SMTP("smtp-relay.sendinblue.com", 587)  # or use 465 for SSL
#         server.starttls()  # Secure the connection
#         server.login(from_addr, password)
#         # Send the email
#         server.sendmail(from_addr, to_addr, msg.as_string())
#         server.quit()
#         print("Email successfully sent!")
#     except Exception as e:
#         print(f"Failed to send email: {e}")


# # Example usage
# send_email(
#     "hello subject",
#     "Thank you guysss",
#     "jaffby1@gmail.com",
#     "1kashtanov1111@gmail.com",
#     "RYj39MNFzvJD6dGx",
# )

# asyncio.run(send_email_async("1kashtanov1111@gmail.com", "llll", "9999"))
from api.routers.auth.classes import JWTToken


print(JWTToken.credentials_exception)
