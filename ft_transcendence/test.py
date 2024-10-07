import pyotp 
import qrcode


key  = "JBSWY3DPEHPK3PXP"
# key = pyotp.random_base32()

# totp = pyotp.TOTP(key)

# while True:
#     print(totp.verify(input("Enter the code: ")))


# uri = pyotp.totp.TOTP(key).provisioning_uri(name="test", issuer_name="test")


# print(uri)


qrcode.make("otpauth://totp/PongyGame:test?secret=JBSWY3DPEHPK3PXP&issuer=PongyGame").save("test.png")

# while True:
#     print(pyotp.totp.TOTP(key).now())

/* Rectangle 277 */

box-sizing: border-box;

position: absolute;
width: 830px;
height: 750px;

background: rgba(22, 22, 37, 0.05);
border: 1px solid #2C3143;
box-shadow: 0px 4px 4px rgba(0, 0, 0, 0.25), 0px 4px 100px rgba(0, 0, 0, 0.25);
