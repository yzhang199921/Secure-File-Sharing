 package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

type ShareID struct {
	ShareUUID uuid.UUID
	ShareKey []byte
}

// The structure definition for a user record
type User struct {
	Username string //username
	Salt []byte //unique salt per user
	PwdSaltHash []byte // Hash of password + salt used to verify pwd
	ArgonKey []byte //pwd based key derivation used for generating other keys using HKDF
	RSAEncPrivKey []byte // private key used for RSA encryption
	SignEcnPrivKey []byte // private key used for digital signature
	Integrity [64]byte //used to check integrity of each user struct
	ShareRecords map[string] ShareID //used to keep track of which files the User is shared with. Stores the UUID of the share record being stored in Datastore. We check Datastore to see if the record exists. 

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.


func checkShareStatus(userdata *User){
	userinfo := *userdata
	for x := range userinfo.ShareRecords {
		shareRecordUUID := userinfo.ShareRecords[x].ShareUUID
		_, checkshare := userlib.DatastoreGet(shareRecordUUID)
		if(!checkshare) {
			delete(userinfo.ShareRecords, x)
		}
	}
}

func pad(blocksize int, message []byte) (padded []byte) {
	m := len(message)
	remainder := m % blocksize
	if(remainder == 0) {
		var padding []byte
		for i := 0; i < blocksize; i++ {
			padding = append(padding, byte(blocksize))
		}
		padded = append(message, padding...)
	} else {
		diff := blocksize - remainder
		var padding []byte
		for i := 0; i < diff; i++ {
			padding = append(padding, byte(diff))
		}
		padded = append(message, padding...)
	}
	return padded
}

func unpad(blocksize int, message []byte) (unpadded []byte, err error) {
	remainder := len(message) % blocksize
	if(len(message) == 0) {
		return nil, err
	}
	if(remainder != 0) {
		return nil, errors.New("ENCRYPTION COMPROMISED")
	}
	padNum := message[len(message)-1]
	unpadded = message[:len(message) - int(padNum)]
	return unpadded, nil
}

func calculateIntegrity(userdata User) (integrity [64]byte) {
	marshalledShareRecord, _ := json.Marshal(userdata.ShareRecords)
	userinfo1 := append([]byte(userdata.Username), userdata.Salt...)
	userinfo2 := append(userinfo1, userdata.ArgonKey...)
	userinfo3 := append(userinfo2, userdata.RSAEncPrivKey...)
	userinfo4 := append(userinfo3, userdata.SignEcnPrivKey...)
	userinfo5 := append(userinfo4, userdata.PwdSaltHash...)
	userinfofinal := append(userinfo5, marshalledShareRecord...)

	//compute integrity hash
	integrity = userlib.Hash(userinfofinal)
	return integrity
}

func makeUUID(input string) (returnUUID uuid.UUID) {
	hashedinput := userlib.Hash([]byte(input))
	returnUUID, _ = uuid.FromBytes(hashedinput[:16])
	return returnUUID
}

func evaluatepassword(password string, salt []byte, HashKey []byte) (result []byte) {
	inputpwdBytes := []byte(password)
	inputpwdSalt := append(salt, inputpwdBytes...)
	result, _ = userlib.HMACEval(HashKey, inputpwdSalt)
	return result
}

func comparePassword(userdata User, input string, HashKey []byte) (flag bool) {
	flag = true
	realpwdsalthash := userdata.PwdSaltHash
	salt := userdata.Salt

	inputpwdSaltHash := evaluatepassword(input, salt, HashKey)
	if(!userlib.HMACEqual(inputpwdSaltHash, realpwdsalthash)) {
		flag = false
		return flag
	}
	return flag
}



func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//TODO: This is a toy implementation.
	// userdata.Username = username
	//End of toy implementation
	
	//Random HashKey
	HashKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}
	//Generate Random Salt Per User
	salt := userlib.RandomBytes(4)

	userUUID := makeUUID(username)
	_, usernameCheck := userlib.DatastoreGet(userUUID)
	if(usernameCheck) {
		return nil, errors.New("OI MATE TRY ANOTHER NAME EH, THIS ONE IS TAKEN")
	} 

	if(len(password) == 0 || len(username) == 0) {
		return nil, errors.New("Enter all the fields mate, we missing something here")
	}

	//Create a PwdSaltHash
	pwdSaltHash := evaluatepassword(password, salt, HashKey)

	//Create ArgonKey
	pwdBytes := []byte(password)
	argon := userlib.Argon2Key(pwdBytes, salt, 16)

	//Create and store pk and sk for RSA and DS
	//RSA
	rPk, rSk, _ := userlib.PKEKeyGen()
	rSkEncryptionKey, _ := userlib.HashKDF(argon, []byte("rSk"))
	rSkEncryptionKey = rSkEncryptionKey[:16]
	marshalledRSK, _ := json.Marshal(rSk)
	paddedmarshalledRSK := pad(userlib.AESBlockSize, marshalledRSK)
	encryptedRSK := userlib.SymEnc(rSkEncryptionKey, userlib.RandomBytes(16), paddedmarshalledRSK)

	//DS
	dSk, dPk, _ := userlib.DSKeyGen()
	dSkEncryptionKey, _ := userlib.HashKDF(argon, []byte("dSk"))
	dSkEncryptionKey = dSkEncryptionKey[:16]
	marshalledDSK, _ := json.Marshal(dSk)
	paddedmarshalledDSK := pad(userlib.AESBlockSize, marshalledDSK)
	encryptedDSK := userlib.SymEnc(dSkEncryptionKey, userlib.RandomBytes(16), paddedmarshalledDSK)


	//Storing in KeyStore
	RSAStorageKey := "RSA" + username
	userlib.KeystoreSet(RSAStorageKey, rPk)
	DSStorageKey := "DS" + username
	userlib.KeystoreSet(DSStorageKey, dPk)

	//Populating the new User structt
	userdata.Username = username
	userdata.PwdSaltHash = pwdSaltHash
	userdata.Salt = salt
	userdata.ArgonKey = argon
	userdata.RSAEncPrivKey = encryptedRSK
	userdata.SignEcnPrivKey = encryptedDSK
	userdata.ShareRecords = make(map[string] ShareID)

	//integrity check
	integrityHash := calculateIntegrity(userdata)
	userdata.Integrity = integrityHash

	//Storing userinfo in DataStore
	marshalledUserData, _ := json.Marshal(userdata) 
	userlib.DatastoreSet(userUUID, marshalledUserData)


	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	HashKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}
	// // username + password match? 
	
	//Check for Username
	userUUID := makeUUID(username)
	userinfo, usernameCheck := userlib.DatastoreGet(userUUID)
	if(!usernameCheck) {
		userlib.DebugMsg("Wrong username")
		return nil, errors.New("OI NAME DOESN'T EXIST, MAYBE TRY CREATING AN ANCCOUNT FIRST MATE")
	}

	//Check for Password
	json.Unmarshal(userinfo, userdataptr)

	checkpassword := comparePassword(userdata, password, HashKey)

	if(!checkpassword) {
		userlib.DebugMsg("Wrong pwd")
		return nil, errors.New("WRONG PASSWORD MATE, IDENTITY THEFT IS NOT A JOKE!!! MILLIONS OF FAMILIES SUFFER EVERY YEAR")
	}

	//compute integrity hash
	integrityHash := calculateIntegrity(userdata)

	if(integrityHash != userdata.Integrity) {
		userlib.DebugMsg("breached")
		return nil, errors.New("WE HAVE A SECURITY BREACH!")
	}


	return userdataptr, nil

}


// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//TODO: This is a toy implementation.
	// UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// packaged_data, _ := json.Marshal(data)
	// userlib.DatastoreSet(UUID, packaged_data)
	//End of toy implementation


	if (userdata == nil) {
		return 
	}

	checkShareStatus(userdata)
	userinfo := *userdata

	//Check Integrity at each step
	userintegrity := calculateIntegrity(userinfo)
	if(userintegrity != userdata.Integrity) {
		return 
	}

	masterKey := userinfo.ArgonKey
	var fileUUID uuid.UUID
	var fileKey []byte
	shareID, checkShare := userinfo.ShareRecords[filename]
	//If file was already shared with the user
	if(checkShare) {
		shareUUID := shareID.ShareUUID
		shareKey := shareID.ShareKey
		encryptedShareRecord, err := userlib.DatastoreGet(shareUUID)
		if(!err) {
			userlib.DebugMsg("Error in retrieving share record info")
			return
		}
		if (len(encryptedShareRecord) % userlib.AESBlockSize != 0) {
			userlib.DebugMsg("Attempting to decrypt something not a multiple of blocksize")
			return 
		}

		if (len(encryptedShareRecord) < userlib.AESBlockSize) {
			return 
		}

		marshalledShareRecord := userlib.SymDec(shareKey, encryptedShareRecord)
		shareRecord := make(map[string] []byte)
		json.Unmarshal(marshalledShareRecord, &shareRecord)
		_, fileKeyCheck := shareRecord["file_key"]
		_, fileUUIDCheck := shareRecord["file_uuid"]
		if(!fileUUIDCheck || !fileKeyCheck) {
			userlib.DebugMsg("Missing fields on shareRecord")
			return
		}
		fileKey = shareRecord["file_key"]
		json.Unmarshal(shareRecord["file_uuid"], &fileUUID)

	} else {
		fileUUID = makeUUID(userinfo.Username + "_" + filename + "_fileRecord")
		fileKey, _ = userlib.HashKDF(masterKey, []byte(filename))
		fileKey = fileKey[:16]
	}

	//Generate tracker for appends
	//Used as a temporary storage for appends, will clear when data is loaded
	var temp []byte
	appendRecord := make(map[string] []byte)

	appendKey, _ := userlib.HashKDF(fileKey, []byte(filename))
	appendKey = appendKey[:16]
	appendRecord["append"] = temp
	appendHMAC, _ := userlib.HMACEval(appendKey, temp)
	appendRecord["append_HMAC"] = appendHMAC

	appendUUID := makeUUID(userinfo.Username + "_" + filename + "_appendRecord")
	marshalledAppendRecord, _ := json.Marshal(appendRecord)
	paddedAppendRecord := pad(userlib.AESBlockSize, marshalledAppendRecord)
	encryptedAppendRecord := userlib.SymEnc(appendKey, userlib.RandomBytes(16), paddedAppendRecord)
	userlib.DatastoreSet(appendUUID, encryptedAppendRecord)


	//Generate hashmap for data and HMAC for integrity
	fileRecord := make(map[string] []byte)
	fileRecord["data"] = data
	fileHMAC, _ := userlib.HMACEval(fileKey, data)
	fileRecord["file_HMAC"] = fileHMAC

	marshalledFileRecord, _ := json.Marshal(fileRecord)
	paddedFileRecord := pad(userlib.AESBlockSize, marshalledFileRecord)
	encryptedFileRecord := userlib.SymEnc(fileKey, userlib.RandomBytes(16), paddedFileRecord)
	userlib.DatastoreSet(fileUUID, encryptedFileRecord)

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	
	
	if (userdata == nil) {
		return errors.New("WHO IS YOU BRUH")
	}

	checkShareStatus(userdata)
	userinfo := *userdata

	//Check Integrity at each step
	userintegrity := calculateIntegrity(userinfo)
	if(userintegrity != userinfo.Integrity) {
		return errors.New("WE HAVE A SECURITY BREACH!!")
	}


	masterKey := userinfo.ArgonKey
	var fileKey []byte
	var appendUUID uuid.UUID
	var appendKey []byte

	shareID, checkShare := userinfo.ShareRecords[filename]
	//If file was already shared with the user
	if(checkShare) {
		shareUUID := shareID.ShareUUID
		shareKey := shareID.ShareKey
		encryptedShareRecord, err := userlib.DatastoreGet(shareUUID)
		if(!err) {
			return errors.New("Cannot find Share Record Info")
		}
		if (len(encryptedShareRecord) % userlib.AESBlockSize != 0) {
			return errors.New("Attempting to decrypt something not a multiple of blocksize")
		}
		if (len(encryptedShareRecord) < userlib.AESBlockSize) {
			return errors.New("Share Record most likely compromised")
		}

		marshalledShareRecord := userlib.SymDec(shareKey, encryptedShareRecord)
		var shareRecord map[string] []byte
		json.Unmarshal(marshalledShareRecord, &shareRecord)
		_, fileKeyCheck := shareRecord["file_key"]
		_, fileUUIDCheck := shareRecord["file_uuid"]
		_, appendUUIDCheck := shareRecord["append_uuid"]
		_, appendKeyCheck := shareRecord["append_key"]
		if(!fileUUIDCheck || !fileKeyCheck || !appendUUIDCheck || !appendKeyCheck) {
			return errors.New("Missing fields on shareRecord")
		}

		json.Unmarshal(shareRecord["append_uuid"], &appendUUID)
		fileKey = shareRecord["file_key"]
		appendKey = shareRecord["append_key"]
	} else {
		fileKey, _ = userlib.HashKDF(masterKey, []byte(filename))
		fileKey = fileKey[:16]
		appendKey, _ = userlib.HashKDF(fileKey, []byte(filename))
		appendKey = appendKey[:16]
		appendUUID = makeUUID(userinfo.Username + "_" + filename + "_appendRecord")
	}

	//download from server
	encryptedAppendRecord, appendFlag := userlib.DatastoreGet(appendUUID)
	if(!appendFlag) {
		return errors.New("Cannot retrieve append reccord")
	}

	if (len(encryptedAppendRecord) % userlib.AESBlockSize != 0) {
		return errors.New("Attempting to decrypt append record not a multiple of blocksize")
	}
	if (len(encryptedAppendRecord) < userlib.AESBlockSize) {
		return errors.New("Append most likely compromised")
	}

	paddedAppendRecord := userlib.SymDec(appendKey, encryptedAppendRecord)
	marshalledAppendRecord, integrity := unpad(userlib.AESBlockSize, paddedAppendRecord)
	if(integrity != nil) {
		return integrity
	}
	appendRecord := make(map[string] []byte)
	json.Unmarshal(marshalledAppendRecord, &appendRecord)
	_, appendDataCheck := appendRecord["append"]
	_, appendHMACCheck := appendRecord["append_HMAC"]
	if(!appendDataCheck || !appendHMACCheck) {
		return errors.New("Missing Fields on Append Record")
	}

	//Check integrity
	appendHMAC, _ := userlib.HMACEval(appendKey, appendRecord["append"])
	if(!userlib.HMACEqual(appendRecord["append_HMAC"], appendHMAC)) {
		return errors.New("APPEND INTEGRITY COMPROMISED")
	}

	//Add our current append in and reupload
	appendRecord["append"] = append(appendRecord["append"],data...)
	appendHMAC, _ = userlib.HMACEval(appendKey, appendRecord["append"])
	appendRecord["append_HMAC"] = appendHMAC

	marshalledAppendRecord, _ = json.Marshal(appendRecord)
	paddedAppendRecord = pad(userlib.AESBlockSize, marshalledAppendRecord)
	encryptedAppendRecord = userlib.SymEnc(appendKey, userlib.RandomBytes(16), paddedAppendRecord)
	userlib.DatastoreSet(appendUUID, encryptedAppendRecord)

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//TODO: This is a toy implementation.
	// UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// packaged_data, ok := userlib.DatastoreGet(UUID)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("File not found!"))
	// }
	// json.Unmarshal(packaged_data, &data)
	// return data, nil
	//End of toy implementation
	
	
	
	if (userdata == nil) {
		return nil, errors.New("WHO IS YOU BRUH")
	}
	checkShareStatus(userdata)
	userinfo := *userdata
	shareID, checkShare := userinfo.ShareRecords[filename]
	//Check Integrity at each step
	userintegrity := calculateIntegrity(userinfo)
	if(userintegrity != userinfo.Integrity) {
		return nil, errors.New("WE HAVE A SECURITY BREACH!!")
	}

	masterKey := userinfo.ArgonKey
	var fileUUID uuid.UUID
	var fileKey []byte
	var appendUUID uuid.UUID
	var appendKey []byte

	
	//File is shared
	if(checkShare) {
		shareUUID := shareID.ShareUUID
		shareKey := shareID.ShareKey
		encryptedShareRecord, err := userlib.DatastoreGet(shareUUID)
		if(!err) {
			return nil, errors.New("Error in retrieving share record info")
		}

		if (len(encryptedShareRecord) % userlib.AESBlockSize != 0) {
			return nil, errors.New("Attempting to decrypt something not a multiple of blocksize")
		}
		if (len(encryptedShareRecord) < userlib.AESBlockSize) {
			return nil, errors.New("Share Record most likely compromised")
		}


		marshalledShareRecord := userlib.SymDec(shareKey, encryptedShareRecord)
		var shareRecord map[string] []byte
		json.Unmarshal(marshalledShareRecord, &shareRecord)
		_, fileKeyCheck := shareRecord["file_key"]
		_, fileUUIDCheck := shareRecord["file_uuid"]
		_, appendUUIDCheck := shareRecord["append_uuid"]
		_, appendKeyCheck := shareRecord["append_key"]
		if(!fileUUIDCheck || !fileKeyCheck || !appendUUIDCheck || !appendKeyCheck) {
			return nil, errors.New("Missing fields on shareRecord")
		}

		json.Unmarshal(shareRecord["file_uuid"], &fileUUID)
		json.Unmarshal(shareRecord["append_uuid"], &appendUUID)
		fileKey = shareRecord["file_key"]
		appendKey = shareRecord["append_key"]
	} else {
		fileUUID = makeUUID(userinfo.Username + "_" + filename + "_fileRecord")
		fileKey, _ = userlib.HashKDF(masterKey, []byte(filename))
		fileKey = fileKey[:16]
		appendKey, _ = userlib.HashKDF(fileKey, []byte(filename))
		appendKey = appendKey[:16]
		appendUUID = makeUUID(userinfo.Username + "_" + filename + "_appendRecord")
	}


	//Download File Record
	encryptedFileRecord, fileFlag := userlib.DatastoreGet(fileUUID)
	if(!fileFlag) {
		return nil, errors.New("Cannot retrieve file record")
	}

	if (len(encryptedFileRecord) % userlib.AESBlockSize != 0) {
		return nil, errors.New("Attempting to decrypt file record not a multiple of blocksize")
	}
	if (len(encryptedFileRecord) < userlib.AESBlockSize) {
		return nil, errors.New("File most likely compromised")
	}

	paddedFileRecord := userlib.SymDec(fileKey, encryptedFileRecord)
	marshalledFileRecord, fileIntegrity := unpad(userlib.AESBlockSize, paddedFileRecord)
	if(fileIntegrity != nil) {
		return nil, fileIntegrity
	}
	fileRecord := make(map[string] []byte) //Store downloaded file record
	json.Unmarshal(marshalledFileRecord, &fileRecord)

	//Check integrity of file record
	fileHMAC, _ := userlib.HMACEval(fileKey, fileRecord["data"])
	if(!userlib.HMACEqual(fileRecord["file_HMAC"], fileHMAC)) {
		return nil, errors.New("FILE INTEGRITY COMPROMISED")
	}
	_, fileDataCheck := fileRecord["data"]
	_, fileHMACCheck := fileRecord["file_HMAC"]
	if(!fileDataCheck || !fileHMACCheck) {
		return nil, errors.New("Missing Fields on File Record")
	}


	//Download Append Record
	encryptedAppendRecord, appendFlag := userlib.DatastoreGet(appendUUID)
	if(!appendFlag) {
		return nil, errors.New("Cannot retrieve append reccord")
	}

	if (len(encryptedAppendRecord) % userlib.AESBlockSize != 0) {
		return nil, errors.New("Attempting to decrypt append record not a multiple of blocksize")
	}

	if (len(encryptedAppendRecord) < userlib.AESBlockSize) {
		return nil, errors.New("Append most likely compromised")
	}


	paddedAppendRecord := userlib.SymDec(appendKey, encryptedAppendRecord)
	marshalledAppendRecord, appendIntegrity := unpad(userlib.AESBlockSize, paddedAppendRecord)
	if(appendIntegrity != nil) {
		return nil, appendIntegrity
	}
	appendRecord := make(map[string] []byte) //stores downloaded append record
	json.Unmarshal(marshalledAppendRecord, &appendRecord)

	_, appendDataCheck := appendRecord["append"]
	_, appendHMACCheck := appendRecord["append_HMAC"]
	if(!appendDataCheck || !appendHMACCheck) {
		return nil, errors.New("Missing Fields on Append Record")
	}

	//Check integrity of append record
	appendHMAC, _ := userlib.HMACEval(appendKey, appendRecord["append"])
	if(!userlib.HMACEqual(appendRecord["append_HMAC"], appendHMAC)) {
		return nil, errors.New("APPEND INTEGRITY COMPROMISED")
	}

	//Extract data from file and append. Then we clear append history
	data = fileRecord["data"]
	data = append(data, appendRecord["append"]...)
	var temp []byte
	appendRecord["append"] = temp
	fileRecord["data"] = data

	//Reupload file record
	fileHMAC, _ = userlib.HMACEval(fileKey, fileRecord["data"])
	fileRecord["file_HMAC"] = fileHMAC
	marshalledFileRecord, _ = json.Marshal(fileRecord)
	paddedFileRecord = pad(userlib.AESBlockSize, marshalledFileRecord)
	encryptedFileRecord = userlib.SymEnc(fileKey, userlib.RandomBytes(16), paddedFileRecord)
	userlib.DatastoreSet(fileUUID, encryptedFileRecord)

	//Reupload both file and append records
	appendHMAC, _ = userlib.HMACEval(appendKey, appendRecord["append"])
	appendRecord["append_HMAC"] = appendHMAC
	marshalledAppendRecord, _ = json.Marshal(appendRecord)
	paddedAppendRecord = pad(userlib.AESBlockSize, marshalledAppendRecord)
	encryptedAppendRecord = userlib.SymEnc(appendKey, userlib.RandomBytes(16), paddedAppendRecord)
	userlib.DatastoreSet(appendUUID, encryptedAppendRecord)

	return data, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	
	
	if (userdata == nil) {
		return "", errors.New("WHO IS YOU BRUH")
	}

	checkShareStatus(userdata)
	userinfo := *userdata

	//Check Integrity at each step
	userintegrity := calculateIntegrity(userinfo)
	if(userintegrity != userinfo.Integrity) {
		return "", errors.New("WE HAVE A SECURITY BREACH!!")
	}
	//Check recipient is alive
	recipientUUID := makeUUID(recipient)
	_, usernameCheck := userlib.DatastoreGet(recipientUUID)
	if(!usernameCheck) {
		return "", errors.New("OI RECIPIENT NAME DOESN'T EXIST, MAYBE TRY CREATING AN ANCCOUNT FIRST MATE")
	}

	masterKey := userinfo.ArgonKey
	//Obtain Recipient Public key used for PKE
	recipientPublicKey, _ := userlib.KeystoreGet("RSA" + recipient)

	shareID, checkShare := userinfo.ShareRecords[filename]
	//The user is trying to share a file that was shared with them
	if(checkShare) {
		//We already have the key and UUID for the Share Record. We just need to send the information securely to the recipient
		encryptedShareKey, _ := userlib.PKEEnc(recipientPublicKey, shareID.ShareKey)
		shareRecordUUID := shareID.ShareUUID

		dSkEncryptionKey, _ := userlib.HashKDF(masterKey, []byte("dSk"))
		dSkEncryptionKey = dSkEncryptionKey[:16]
		paddedSignKey := userlib.SymDec(dSkEncryptionKey, userinfo.SignEcnPrivKey)
		marshalledSignKey, signKeyIntegrity := unpad(userlib.AESBlockSize, paddedSignKey)
		if(signKeyIntegrity != nil) {
			return "", signKeyIntegrity
		}
		var signKey userlib.PrivateKeyType
		json.Unmarshal(marshalledSignKey, &signKey)
		marshalledShareUUID, _ := json.Marshal(shareRecordUUID)
		signature, _ := userlib.DSSign(signKey, append(encryptedShareKey, marshalledShareUUID...))
		token := append([]byte(recipient), append(signature, append(encryptedShareKey, marshalledShareUUID...)...)...)
		magic_string = string(token)
		return magic_string, err
	}

	//Else, we create a new share record in Datastore and encrypt
	shareRecord := make(map[string] []byte)

	fileUUID := makeUUID(userinfo.Username + "_" + filename + "_fileRecord")
	fileKey, _ := userlib.HashKDF(masterKey, []byte(filename))
	fileKey = fileKey[:16]
	appendKey, _ := userlib.HashKDF(fileKey, []byte(filename))
	appendKey = appendKey[:16]
	appendUUID := makeUUID(userinfo.Username + "_" + filename + "_appendRecord")

	marshalledFileUUID, _ := json.Marshal(fileUUID)
	marshalledAppendUUID, _ := json.Marshal(appendUUID)

	shareRecord["file_key"] = fileKey
	shareRecord["append_key"] = appendKey
	shareRecord["file_uuid"] = marshalledFileUUID
	shareRecord["append_uuid"] = marshalledAppendUUID

	marshalledShareRecord, _ := json.Marshal(shareRecord)
	paddedShareRecord := pad(userlib.AESBlockSize, marshalledShareRecord)

	shareRecordUUID := makeUUID(userinfo.Username + "_Shared_" + filename + "_With_" + recipient)
	shareKey, _ := userlib.HashKDF(masterKey, []byte(userinfo.Username + "_Shared_" + filename + "_With_" + recipient))
	shareKey = shareKey[:16]
	integrity, _ := userlib.HMACEval(shareKey, append(append(append(fileKey, marshalledFileUUID...), appendKey...), marshalledAppendUUID...))
	shareRecord["integrity"] = integrity 

	encryptedShareRecord := userlib.SymEnc(shareKey, userlib.RandomBytes(16), paddedShareRecord)
	userlib.DatastoreSet(shareRecordUUID, encryptedShareRecord)

	//Perform the same encryption as above and send the information 
	encryptedShareKey, _ := userlib.PKEEnc(recipientPublicKey, shareKey)

	dSkEncryptionKey, _ := userlib.HashKDF(masterKey, []byte("dSk"))
	dSkEncryptionKey = dSkEncryptionKey[:16]
	paddedSignKey := userlib.SymDec(dSkEncryptionKey, userinfo.SignEcnPrivKey)
	marshalledSignKey, signKeyIntegrity := unpad(userlib.AESBlockSize, paddedSignKey)
	if(signKeyIntegrity != nil) {
		return "", signKeyIntegrity
	}
	var signKey userlib.PrivateKeyType
	json.Unmarshal(marshalledSignKey, &signKey)
	marshalledShareUUID, _ := json.Marshal(shareRecordUUID)
	signature, _ := userlib.DSSign(signKey, append(encryptedShareKey, marshalledShareUUID...))
	token := append([]byte(recipient), append(signature, append(encryptedShareKey, marshalledShareUUID...)...)...)
	magic_string = string(token)
	return magic_string, err

}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	if (userdata == nil) {
		return errors.New("WHO IS YOU BRUH")
	}
	userinfo := *userdata
	//Check Integrity at each step
	userintegrity := calculateIntegrity(userinfo)
	if(userintegrity != userinfo.Integrity) {
		return errors.New("WE HAVE A SECURITY BREACH!!")
	}
	//Check recipient is alive
	senderUUID := makeUUID(sender)
	_, usernameCheck := userlib.DatastoreGet(senderUUID)
	if(!usernameCheck) {
		return errors.New("OI SENDER NAME DOESN'T EXIST, MAYBE TRY CREATING AN ACCOUNT FIRST MATE")
	}


	//Check unique filename
	currFileUUID := makeUUID(userinfo.Username + "_" + filename + "_fileRecord")
	_, checkname := userlib.DatastoreGet(currFileUUID)
	if(checkname) {
		return errors.New("File already exists for you mate")
	}

	masterKey := userinfo.ArgonKey
	if (len(magic_string) == 0) {
		return errors.New("Where's the magic string bruv")
	}
	token := []byte(magic_string)

	if (len(token) < 512) {
		return errors.New("TOKEN COMPROMISED")
	}

	byteRecipient := []byte(userinfo.Username)
	recipient := token[:len(byteRecipient)]
	if(string(recipient) != userinfo.Username) {
		return errors.New("You tryna intercept a magic string mate?")
	}

	signature := token[len(byteRecipient):len(byteRecipient)+256]
	encryptedShareKey := token[len(byteRecipient)+256:len(byteRecipient)+512]
	marshalledShareUUID := token[len(byteRecipient)+512:]
	var shareUUID uuid.UUID
	json.Unmarshal(marshalledShareUUID, &shareUUID)

	verifySignKey, exists := userlib.KeystoreGet("DS" + sender)
	if(!exists) {
		return errors.New("CANNOT FIND SENDER VERIFICATION KEY")
	}

	verified := userlib.DSVerify(verifySignKey, append(encryptedShareKey, marshalledShareUUID...), signature)
	if(verified != nil) {
		return verified
	}

	//We create a new ShareID for the recipient
	rSkEncryptionKey, _ := userlib.HashKDF(masterKey, []byte("rSk"))
	rSkEncryptionKey = rSkEncryptionKey[:16]
	paddedEncryptionKey := userlib.SymDec(rSkEncryptionKey, userinfo.RSAEncPrivKey)
	marshalledEncKey, encKeyIntegrity := unpad(userlib.AESBlockSize, paddedEncryptionKey)
	if (encKeyIntegrity != nil) {
		return encKeyIntegrity
	}
	var rsaDecKey userlib.PrivateKeyType
	json.Unmarshal(marshalledEncKey, &rsaDecKey)

	shareRecordKey, _ := userlib.PKEDec(rsaDecKey, encryptedShareKey)


	var shareID ShareID
	shareID.ShareUUID = shareUUID
	shareID.ShareKey = shareRecordKey

	userinfo.ShareRecords[filename] = shareID
	integrity := calculateIntegrity(userinfo)
	userdata.Integrity = integrity

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	
	
	if (userdata == nil) {
		return errors.New("WHO IS YOU BRUH")
	}

	checkShareStatus(userdata)
	userinfo := *userdata

	//Check Integrity at each step
	userintegrity := calculateIntegrity(userinfo)
	if(userintegrity != userinfo.Integrity) {
		return errors.New("WE HAVE A SECURITY BREACH!!")
	}
	//Check target is alive
	targetUUID := makeUUID(target_username)
	_, usernameCheck := userlib.DatastoreGet(targetUUID)
	if(!usernameCheck) {
		return errors.New("OI TARGET NAME DOESN'T EXIST, MAYBE TRY CREATING AN ACCOUNT FIRST MATE")
	}

	_, checkFile := userdata.LoadFile(filename)
	if(checkFile != nil) { 
		return checkFile
	}

	shareRecordUUID := makeUUID(userinfo.Username + "_Shared_" + filename + "_With_" + target_username)
	_, shareRecordCheck := userlib.DatastoreGet(shareRecordUUID)
	if (!shareRecordCheck) {
		return errors.New("NO SHARE RECORD BRUH")
	}

	userlib.DatastoreDelete(shareRecordUUID)
	
	return
}
