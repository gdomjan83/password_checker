#This script checks one or several passwords in the database of haveibeenpwned.com, seeing if the password had been leaked or breached in the past
#Good way to check if the password you are using is still secure or not
#Enter passwords either in the terminal (E.g: > check_pass.py hello password test <- this checks the passwords: hello, password, test)
#or list passwords in the pass.text file, which must be in the same folder as this script
from os import path
import sys
import hashlib
import requests

url = "https://api.pwnedpasswords.com/range/"

def get_hashed_password(password):
	#encrypt password into sha1
	hash_pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
	return hash_pwd

def get_api_request(password):
	hash_pwd = get_hashed_password(password)
	#split sha1 password (first five character and the rest)
	pwd_first_five, pwd_tail = hash_pwd[:5], hash_pwd[5:]
	#call API with first five character of the hashed password
	req = requests.get(url + pwd_first_five)
	if (req.status_code != 200):
		raise RuntimeError("API error. Check the API url!")
	return (req, pwd_tail)


def check_hacked_password(password):
	req, pwd_tail = get_api_request(password)
	responses = [line.split(":") for line in req.text.splitlines()]
	#search in the returned API for our password
	for tail, count in responses:
		if (tail == pwd_tail):
			return count
	
def main(args):
	for password in args:
		count = check_hacked_password(password)
		#print result
		if count:
			print(f"The password \"{password}\" has been breached {count} times. I suggest to find another password.")
		else:
			print(f"The password \"{password}\" has not been breached yet.")

if (__name__ == "__main__"):
	#checks for passwords added from the terminal. E.g: > check_pass.py hello password test <- this checks the passwords: hello, password, test
	if (sys.argv):
		main(sys.argv[1:])

	#if there is pass.txt file in the folder of the script, you can use it to check for the passwords present in the file, the passwords must be entered in separate lines
	if (path.exists(".\pass.txt")):
		with (open(".\pass.txt", "r")) as file:
			main(file.read().splitlines())
