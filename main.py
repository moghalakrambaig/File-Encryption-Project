print("1.Generate keys")
print("2.Encryption")
print("3.Decryption")
choose = str(raw_input("Choose Any one option : "))
if(choose == '1'):
    print ("Key Generation in progress...")
    #importing crypto module
    from Crypto.PublicKey import RSA

    #Generate a public/ private key pair using 4096 bits key length (512 bytes)
    new_key = RSA.generate(4096, e=3073)
    
    #The private key in PEM format
    private_key = new_key.exportKey("PEM")

    #The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")
    
    print ("private_key Generation Completed!")
    fd = open("private_key.pem", "wb")
    fd.write(private_key)
    fd.close()

    print ("public_key Generation Completed!")
    fd = open("public_key.pem", "wb")
    fd.write(public_key)
    fd.close()


elif(choose == '2'):
    #ch9_encrypt_blob.py
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    import zlib
    import base64

    #Our Encryption Function
    def encrypt_blob(blob, public_key):
        #Import the Public Key and use for encryption using PKCS1_OAEP
        rsa_key = RSA.importKey(public_key)
        rsa_key = PKCS1_OAEP.new(rsa_key)
    
        #compress the data first
        blob = zlib.compress(blob)

        #In determining the chunk size, determine the private key length used in bytes
        #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
        #in chunks
        chunk_size = 470
        offset = 0
        end_loop = False
        encrypted =  ""

        while not end_loop:
            #The chunk
            chunk = blob[offset:offset + chunk_size]

            #If the data chunk is less then the chunk size, then we need to add
            #padding with " ". This indicates the we reached the end of the file
            #so we end loop here
            if len(chunk) % chunk_size != 0:
                end_loop = True
                chunk += " " * (chunk_size - len(chunk))

            #Append the encrypted chunk to the overall encrypted file

            encrypted += rsa_key.encrypt(chunk)

            #Increase the offset by chunk size
            offset += chunk_size

        #Base 64 encode the encrypted file
        return base64.b64encode(encrypted)

    #Use the public key for encryption
    fd = open("public_key.pem", "rb")
    public_key = fd.read()
    fd.close()

    #Our candidate file to be encrypted
    #files1 = str(input("Enter File name : "))
    filename = raw_input("Enter the file name :")
    print ("Encryption Process in progress...")
    fd = open(filename, "rb")
    unencrypted_blob = fd.read()
    fd.close()

    encrypted_blob = encrypt_blob(unencrypted_blob, public_key)

    #Write the encrypted contents to a file
    filename1 = raw_input("Enter file name for the encrypted file:")
    fd = open(filename1, "wb")
    fd.write(encrypted_blob)
    fd.close()
    print("Encryption Process Completed..!!")

elif(choose == '3'):
    #ch9_decrypt_blob.py
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    import base64
    import zlib

    #Our Decryption Function
    def decrypt_blob(encrypted_blob, private_key):

        #Import the Private Key and use for decryption using PKCS1_OAEP
        rsakey = RSA.importKey(private_key)
        rsakey = PKCS1_OAEP.new(rsakey)

        #Base 64 decode the data
        encrypted_blob = base64.b64decode(encrypted_blob)

        #In determining the chunk size, determine the private key length used in bytes.
        #The data will be in decrypted in chunks
        chunk_size = 512
        offset = 0
        decrypted = ""

        #keep loop going as long as we have chunks to decrypt
        while offset < len(encrypted_blob):
            #The chunk
            chunk = encrypted_blob[offset: offset + chunk_size]

            #Append the decrypted chunk to the overall decrypted file
            decrypted += rsakey.decrypt(chunk)

            #Increase the offset by chunk size
            offset += chunk_size

        #return the decompressed decrypted data
        return zlib.decompress(decrypted)

    #Use the private key for decryption
    fd = open("private_key.pem", "rb")
    private_key = fd.read()
    fd.close()

    #Our candidate file to be decrypted
    Dfilename = raw_input("Enter the name of the file to be Decrypted :")
    fd = open(Dfilename, "rb")
    encrypted_blob = fd.read()
    fd.close()

    #Write the decrypted contents to a file
    Dfilename1 = raw_input("Enter a name for the decrypted file :")
    print ("Decryption Process in progress...")
    fd = open(Dfilename1, "wb")
    fd.write(decrypt_blob(encrypted_blob, private_key))
    fd.close()
    print("Decryption Process Completed..!!")